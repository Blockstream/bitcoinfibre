// Copyright (c) 2016, 2017 Matt Corallo
// Copyright (c) 2019 Blockstream
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <udpnet.h>
#include <udprelay.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <compat/endian.h>
#include <crypto/poly1305.h>
#include <hash.h>
#include <init.h> // for ShutdownRequested()
#include <validation.h>
#include <net.h>
#include <netbase.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <txmempool.h>
#include <logging.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <event2/event.h>

#include <boost/thread.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <thread>

#ifndef WIN32
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#endif

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

template <typename Duration>
double to_seconds(Duration d)
{
    return std::chrono::duration_cast<std::chrono::duration<double, std::chrono::seconds::period>>(d).count();
}

static std::vector<int> udp_socks; // The sockets we use to send/recv (bound to *:GetUDPInboundPorts()[*])

std::recursive_mutex cs_mapUDPNodes;
std::map<CService, UDPConnectionState> mapUDPNodes;
std::atomic<uint64_t> min_per_node_mbps(1024);
bool maybe_have_write_nodes;

static std::map<int64_t, std::tuple<CService, uint64_t, size_t> > nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;

static int mcastStatPrintInterval = 10;

/*
 * UDP multicast service
 *
 * Unlike the main UDP communication mechanism, the multicast service does not
 * require a "connection". The multicast Tx node transmits messages without ever
 * knowing about the existing receivers and receivers only need to listen to a
 * particular multicast ip:port by joining the multicast group.
 */
namespace {
    std::map<std::tuple<CService, int, uint16_t>, UDPMulticastInfo> mapMulticastNodes;
    char const* const multicast_pass = "multicast";
    uint64_t const multicast_magic = Hash(&multicast_pass[0], &multicast_pass[0] + strlen(multicast_pass)).GetUint64(0);
}
uint64_t const multicast_checksum_magic = htole64(multicast_magic);

//TODO: The checksum stuff is not endian-safe (esp the poly impl):
static void FillChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));

    uint8_t key[POLY1305_KEYLEN]; // (32 bytes)
    memcpy(key,      &magic, sizeof(magic));
    memcpy(key + 8,  &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[POLY1305_TAGLEN]; // (16 bytes)
    poly1305_auth(hash, (unsigned char*)&msg.header.msg_type, length - 16, key);
    memcpy(&msg.header.chk1, hash, sizeof(msg.header.chk1));
    memcpy(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));

    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type) [i+j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }
}
static bool CheckChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));
    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type) [i+j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }

    uint8_t key[POLY1305_KEYLEN]; // (32 bytes)
    memcpy(key,      &magic, sizeof(magic));
    memcpy(key + 8,  &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[POLY1305_TAGLEN]; // (16 bytes)
    poly1305_auth(hash, (unsigned char*)&msg.header.msg_type, length - 16, key);
    return !memcmp(&msg.header.chk1, hash, sizeof(msg.header.chk1)) && !memcmp(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));
}



/**
 * Init/shutdown logic follows
 */

static struct event_base* event_base_read = nullptr;
static event *timer_event;
static std::vector<event*> read_events;
static struct timeval timer_interval;

// ~10MB of outbound messages pending
static const size_t PENDING_MESSAGES_BUFF_SIZE = 8192;
static const double max_tx_group_turn_duration = 0.2; // seconds
static std::atomic_bool send_messages_break(false);
std::mutex send_messages_mutex;
std::condition_variable send_messages_wake_cv;
struct PendingMessagesBuff {
    std::tuple<CService, UDPMessage, unsigned int, uint64_t> messagesPendingRingBuff[PENDING_MESSAGES_BUFF_SIZE];
    std::atomic<uint16_t> nextPendingMessage, nextUndefinedMessage;
    PendingMessagesBuff() : nextPendingMessage(0), nextUndefinedMessage(0) {}
};
struct MessageStateCache {
    ssize_t buff_id;
    uint16_t nextPendingMessage;
    uint16_t nextUndefinedMessage;
};
struct PerQueueSendState {
    MessageStateCache buff_state;
    std::chrono::steady_clock::time_point next_send;
    std::chrono::steady_clock::time_point last_send;
};
struct PerGroupMessageQueue {
    std::array<PendingMessagesBuff, 4> buffs;
    /* Three message queues (buffers) per group:
     * 0) high priority
     * 1) best-effort (non priority)
     * 2) background txns (used by txn thread)
     * 3) background blocks (used by backfill thread)
     *
     * The current buffer is indicated by `state.buff_id`. This id is set to -1
     * when all buffers are empty.
     */

    /* Find the next buffer with data available for transmission, while
     * respecting buffer priorities. */
    inline MessageStateCache NextBuff() {
        for (size_t i = 0; i < buffs.size(); i++) {
            uint16_t next_undefined_message = buffs[i].nextUndefinedMessage;
            uint16_t next_pending_message = buffs[i].nextPendingMessage;
            if (next_undefined_message != next_pending_message)
                return {(ssize_t)i, next_pending_message, next_undefined_message};
        }
        return {-1, 0, 0};
    }

    uint64_t bw;
    bool multicast;
    double byte_quota;
    double target_bytes_per_sec;
    double max_byte_quota_per_turn;
    struct PerQueueSendState state;
    PerGroupMessageQueue() : bw(0), multicast(false), byte_quota(0), target_bytes_per_sec(0), max_byte_quota_per_turn(0) {}
    PerGroupMessageQueue(PerGroupMessageQueue&& q) =delete;
};
static std::map<size_t, PerGroupMessageQueue> mapTxQueues;

static void ThreadRunReadEventLoop() { event_base_dispatch(event_base_read); }
static void do_send_messages();
static void send_messages_flush_and_break();
static std::map<size_t, PerGroupMessageQueue> init_tx_queues(const std::vector<std::pair<unsigned short, uint64_t> >& group_list,
                                                             const std::vector<UDPMulticastInfo>& multicast_list);
static void ThreadRunWriteEventLoop() { do_send_messages(); }

static void read_socket_func(evutil_socket_t fd, short event, void* arg);
static void timer_func(evutil_socket_t fd, short event, void* arg);

static std::unique_ptr<std::thread> udp_read_thread;
static std::vector<std::thread> udp_write_threads;

static void OpenMulticastConnection(const CService& service, bool multicast_tx, size_t group, bool trusted);
static UDPMulticastInfo ParseUDPMulticastInfo(const std::string& s, bool tx);
static std::vector<UDPMulticastInfo> GetUDPMulticastInfo();

static void MulticastBackfillThread(const CService& mcastNode, const UDPMulticastInfo *info);
static void LaunchMulticastBackfillThreads();
static std::vector<std::thread> mcast_tx_threads;


static void AddConnectionFromString(const std::string& node, bool fTrust) {
    size_t host_port_end = node.find(',');
    size_t local_pass_end = node.find(',', host_port_end + 1);
    size_t remote_pass_end = node.find(',', local_pass_end + 1);
    size_t group_end = node.find(',', remote_pass_end + 1);
    if (host_port_end == std::string::npos || local_pass_end == std::string::npos || (remote_pass_end != std::string::npos && group_end != std::string::npos)) {
        LogPrintf("UDP: Failed to parse parameter to -add[trusted]udpnode: %s\n", node);
        return;
    }

    std::string host_port = node.substr(0, host_port_end);
    CService addr;
    if (!Lookup(host_port.c_str(), addr, -1, true) || !addr.IsValid()) {
        LogPrintf("UDP: Failed to lookup hostname for -add[trusted]udpnode: %s\n", host_port);
        return;
    }

    std::string local_pass = node.substr(host_port_end + 1, local_pass_end - host_port_end - 1);
    uint64_t local_magic = Hash(&local_pass[0], &local_pass[0] + local_pass.size()).GetUint64(0);

    std::string remote_pass;
    if(remote_pass_end == std::string::npos)
        remote_pass = node.substr(local_pass_end + 1);
    else
        remote_pass = node.substr(local_pass_end + 1, remote_pass_end - local_pass_end - 1);
    uint64_t remote_magic = Hash(&remote_pass[0], &remote_pass[0] + local_pass.size()).GetUint64(0);

    size_t group = 0;
    if (remote_pass_end != std::string::npos) {
        std::string group_str(node.substr(remote_pass_end + 1));
        group = atoi64(group_str);
    }

    OpenPersistentUDPConnectionTo(addr, local_magic, remote_magic, fTrust, UDP_CONNECTION_TYPE_NORMAL, group, udp_mode_t::unicast);
}

static void AddConfAddedConnections() {
    if (gArgs.IsArgSet("-addudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addudpnode")) {
            AddConnectionFromString(node, false);
        }
    }
    if (gArgs.IsArgSet("-addtrustedudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addtrustedudpnode")) {
            AddConnectionFromString(node, true);
        }
    }
}

static void CloseSocketsAndReadEvents() {
    for (event* ev : read_events)
        event_free(ev);
    for (int sock : udp_socks)
        close(sock);
    read_events.clear();
    udp_socks.clear();
}

/* Find the IPv4 address corresponding to a given interface name */
static struct in_addr GetIfIpAddr(const char* const ifname) {
    struct ifaddrs* myaddrs;
    struct in_addr res_sin_addr;
    bool if_ip_found = false;

    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                char astring[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(s4->sin_addr), astring, INET_ADDRSTRLEN);
                if (strcmp(ifa->ifa_name, ifname) == 0) {
                    res_sin_addr = s4->sin_addr;
                    if_ip_found = true;
                    break;
                }
            }
        }
        freeifaddrs(myaddrs);
    }

    if (!if_ip_found) {
        LogPrintf("UDP: find IP address of interface %s\n", ifname);
        throw std::runtime_error("Couldn't find IP address");
    }

    return res_sin_addr;
}

/**
 * Initialize multicast tx/rx services
 *
 * Initialize the multicast tx services configured via `udpmulticasttx` and the
 * multicast reception groups configured via `udpmulticast`.
 */
static bool InitializeUDPMulticast(std::vector<int> &udp_socks,
                                   std::vector<UDPMulticastInfo> &multicast_list) {
    int group = udp_socks.size() - 1;
    std::vector<std::pair<CService, int>> tx_addr_ifindex_vec;
    std::set<std::pair<CService, int>> tx_addr_ifindex_set;

    for (auto& mcast_info : multicast_list) {
        udp_socks.push_back(socket(AF_INET6, SOCK_DGRAM, 0));
        assert(udp_socks.back());
        mcast_info.fd = udp_socks.back();

        int opt = 1;
        if (setsockopt(udp_socks.back(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
            LogPrintf("UDP: setsockopt failed: %s\n", strerror(errno));
            return false;
        }

        opt = 0;
        if (setsockopt(udp_socks.back(), IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0) {
            LogPrintf("UDP: setsockopt failed: %s\n", strerror(errno));
            return false;
        }

        fcntl(udp_socks.back(), F_SETFL, fcntl(udp_socks.back(), F_GETFL) | O_NONBLOCK);

        /* Bind socket to the multicast service UDP port for any IP address */
        unsigned short multicast_port = mcast_info.port;

        struct sockaddr_in6 wildcard;
        memset(&wildcard, 0, sizeof(wildcard));
        wildcard.sin6_family = AF_INET6;
        memcpy(&wildcard.sin6_addr, &in6addr_any, sizeof(in6addr_any));
        wildcard.sin6_port = htons(multicast_port);

        if (bind(udp_socks.back(), (sockaddr*) &wildcard, sizeof(wildcard))) {
            LogPrintf("UDP: bind failed: %s\n", strerror(errno));
            return false;
        }

        /* Get index of network interface */
        const int ifindex = if_nametoindex(mcast_info.ifname);
        if (ifindex == 0) {
            LogPrintf("Error: couldn't find an index for interface %s: %s\n",
                      mcast_info.ifname, strerror(errno));
            return false;
        }

        /* Get network interface IPv4 address */
        struct in_addr imr_interface = GetIfIpAddr(mcast_info.ifname);
        char imr_interface_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &imr_interface, imr_interface_str,
                  INET_ADDRSTRLEN);

        struct sockaddr_in multicastaddr;
        memset(&multicastaddr, 0, sizeof(multicastaddr));

        /* Is this a multicast Tx group? i.e. if target bandwidth is defined */
        if (mcast_info.tx) {
            LogPrintf("UDP: bind multicast Tx socket %d to interface %s\n",
                      udp_socks.back(), mcast_info.ifname);

            /* Don't loop messages that we send back to us */
            int no_loop = 0;
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_MULTICAST_LOOP, &no_loop, sizeof(no_loop)) != 0) {
                LogPrintf("UDP: setsockopt(IP_MULTICAST_LOOP) failed: %s\n", strerror(errno));
                return false;
            }

            /* Set TTL of multicast messages */
            int ttl = mcast_info.ttl;
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0) {
                LogPrintf("UDP: setsockopt(IP_MULTICAST_TTL) failed: %s\n", strerror(errno));
                return false;
            }

            /* Ensure multicast packets are tx'ed by the chosen interface
             *
             * NOTE: the preceding binding restricts the device used for
             * reception, whereas the option that follows determines the
             * device for transmission. */
            struct ip_mreqn req;
            memset(&req, 0, sizeof(req));
            req.imr_ifindex = ifindex;
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_MULTICAST_IF, &req, sizeof(req)) != 0) {
                LogPrintf("UDP: setsockopt(IP_MULTICAST_IF) failed: %s\n", strerror(errno));
                return false;
            }

            /* DSCP */
            char dscp = mcast_info.dscp; //IPTOS_THROUGHPUT;
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_TOS, &dscp, sizeof(dscp)) != 0) {
                LogPrintf("UDP: setsockopt failed: %s\n", strerror(errno));
                return false;
            }

            /* CService identifier: destination multicast IP address */
            inet_pton(AF_INET, mcast_info.mcast_ip, &multicastaddr.sin_addr);
        } else {
            /* Multicast Rx mode */

            /* Make receive buffer large enough to hold 10000 max-length packets */
            const int rcvbuf = 10000*PACKET_SIZE;
            if (setsockopt(udp_socks.back(), SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) != 0) {
                LogPrintf("UDP: setsockopt(SO_RCVBUF) failed: %s\n", strerror(errno));
                return false;
            }

            /* It is possible that the kernel does not set the size we asked
             * for, so double check: */
            int actual_rcvbuf;
            socklen_t optlen = sizeof(actual_rcvbuf);
            if (getsockopt(udp_socks.back(), SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf, &optlen) != 0) {
                LogPrintf("UDP: getsockopt(SO_RCVBUF) failed: %s\n", strerror(errno));
                return false;
            }

            if (actual_rcvbuf < rcvbuf) {
                LogPrintf("UDP: setsockopt(SO_RCVBUF) tried to set buffer size of %d bytes, but got %d bytes.\n"
                          "Please check and configure the maximum receive buffer size allowed in the OS.\n",
                          rcvbuf, actual_rcvbuf);
#ifdef __linux__
                const int tgtbuf = (2*rcvbuf) + 8;
                LogPrintf("UDP: You can check by running:\n\n> sysctl net.core.rmem_max\n\n"
                          "If the maximum is less than %d, you can increase it by running:\n\n"
                          "> sysctl -w net.core.rmem_max=%d\n\n",
                          rcvbuf, tgtbuf, tgtbuf);
#endif
                return false;
            }

            /* Join multicast group, but only allow multicast packets from a
             * specific source address */
            struct ip_mreq_source req;
            memset(&req, 0, sizeof(req));
            inet_pton(AF_INET, mcast_info.mcast_ip, &(req.imr_multiaddr));
            req.imr_interface = imr_interface;
            inet_pton(AF_INET, mcast_info.tx_ip, &(req.imr_sourceaddr));

            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &req, sizeof(req)) != 0) {
                LogPrintf("UDP: setsockopt(IP_ADD_SOURCE_MEMBERSHIP) failed: %s\n", strerror(errno));
                return false;
            }

            /* CService identifier: Tx node IP address (source address). On
             * "read_socket_func", the source address obtained by "recvfrom"
             * is used in order to find the corresponding CService */
            inet_pton(AF_INET, mcast_info.tx_ip, &multicastaddr.sin_addr);

            LogPrintf("UDP: multicast rx -  multiaddr: %s, interface: %s (%s)"
                      ", sourceaddr: %s, trusted: %u\n",
                      mcast_info.mcast_ip,
                      mcast_info.ifname,
                      imr_interface_str,
                      mcast_info.tx_ip,
                      mcast_info.trusted);
        }

        group++;
        mcast_info.group = group;
        /* For multicast Rx, don't care about the UDP port of the Tx node */
        const unsigned short cservice_port = mcast_info.tx ? multicast_port : 0;
        const CService addr{multicastaddr.sin_addr, cservice_port};

        /* Each address-ifindex pair is associated to an unique physical
         * index. Tx streams sharing the same physical index are configured with
         * different (unique) logical stream indexes. */
        if (mcast_info.tx) {
            const auto addr_ifindex_pair = std::make_pair(addr, ifindex);
            mcast_info.logical_idx       = std::count(tx_addr_ifindex_vec.begin(), tx_addr_ifindex_vec.end(), addr_ifindex_pair);
            if (tx_addr_ifindex_set.count(addr_ifindex_pair))
                mcast_info.physical_idx = std::distance(tx_addr_ifindex_set.begin(), tx_addr_ifindex_set.find(addr_ifindex_pair));
            else
                mcast_info.physical_idx = tx_addr_ifindex_set.size();
            tx_addr_ifindex_vec.push_back(addr_ifindex_pair);
            tx_addr_ifindex_set.insert(addr_ifindex_pair);

            LogPrintf("UDP: multicast tx %lu-%lu -  multiaddr: %s interface: %s ttl: %d depth: %d, interleave: %d\n",
                      mcast_info.physical_idx,
                      mcast_info.logical_idx,
                      mcast_info.mcast_ip,
                      mcast_info.ifname,
                      mcast_info.ttl,
                      mcast_info.depth,
                      mcast_info.interleave_size);
        }

        /* Index based on multicast "addr", ifindex and logical index
         *
         * On udpmulticasttx, the logical stream index is unique among instances
         * that share the same addr-ifindex pair, whereas all udpmulticast (Rx)
         * instances have the same stream index.
         *
         * As a result, in Rx it is only possible to receive from the same
         * source address if the network interface differs. In contrast, in tx,
         * it is possible to feed two or more streams to the same destination
         * multicast address and the same network interface. This is used to
         * multiplex logical multicast streams with different rates and
         * coverages of past blocks.
         *
         * NOTE: on udpmulticasttx, "addr" is the destination multicast address,
         * while on udpmulticast (rx), "addr" is the source address.
         */
        const auto mcast_map_key = std::make_tuple(addr, ifindex,
                                                   mcast_info.logical_idx);
        if (mapMulticastNodes.count(mcast_map_key) > 0) {
            LogPrintf("UDP: error - multicast instance (%s, %s, %d) already exists\n",
                      addr.ToString(), ifindex, mcast_info.logical_idx);
            return false;
        }
        mapMulticastNodes[mcast_map_key] = mcast_info;

        LogPrintf("UDP: Socket %d bound to port %hd for multicast group %d %s\n",
                  udp_socks.back(), multicast_port, group,
                  mcast_info.groupname);
    }

    return true;
}

bool InitializeUDPConnections() {
    assert(udp_write_threads.empty() && !udp_read_thread);

    if (gArgs.IsArgSet("-udpmulticastloginterval") && (atoi(gArgs.GetArg("-udpmulticastloginterval", "")) > 0))
        mcastStatPrintInterval = atoi(gArgs.GetArg("-udpmulticastloginterval", ""));

    const std::vector<std::pair<unsigned short, uint64_t> > group_list(GetUDPInboundPorts());
    for (std::pair<unsigned short, uint64_t> port : group_list) {
        udp_socks.push_back(socket(AF_INET6, SOCK_DGRAM, 0));
        assert(udp_socks.back());

        int opt = 1;
        assert(setsockopt(udp_socks.back(), SOL_SOCKET, SO_REUSEADDR, &opt,  sizeof(opt)) == 0);
        opt = 0;
        assert(setsockopt(udp_socks.back(), IPPROTO_IPV6, IPV6_V6ONLY, &opt,  sizeof(opt)) == 0);
        fcntl(udp_socks.back(), F_SETFL, fcntl(udp_socks.back(), F_GETFL) | O_NONBLOCK);

        struct sockaddr_in6 wildcard;
        memset(&wildcard, 0, sizeof(wildcard));
        wildcard.sin6_family = AF_INET6;
        memcpy(&wildcard.sin6_addr, &in6addr_any, sizeof(in6addr_any));
        wildcard.sin6_port = htons(port.first);

        if (bind(udp_socks.back(), (sockaddr*) &wildcard, sizeof(wildcard))) {
            CloseSocketsAndReadEvents();
            return false;
        }

        LogPrintf("UDP: Bound to port %hd for group %lu with %lu Mbps\n", port.first, udp_socks.size() - 1, port.second);
    }

    event_base_read = event_base_new();
    if (!event_base_read) {
        CloseSocketsAndReadEvents();
        return false;
    }

    auto multicast_list = GetUDPMulticastInfo();

    if (!InitializeUDPMulticast(udp_socks, multicast_list)) {
        CloseSocketsAndReadEvents();
        return false;
    }

    for (int socket : udp_socks) {
        event *read_event = event_new(event_base_read, socket, EV_READ | EV_PERSIST, read_socket_func, nullptr);
        if (!read_event) {
            event_base_free(event_base_read);
            CloseSocketsAndReadEvents();
            return false;
        }
        read_events.push_back(read_event);
        event_add(read_event, nullptr);
    }

    timer_event = event_new(event_base_read, -1, EV_PERSIST, timer_func, nullptr);
    if (!timer_event) {
        CloseSocketsAndReadEvents();
        event_base_free(event_base_read);
        return false;
    }
    timer_interval.tv_sec = 0;
    timer_interval.tv_usec = 500*1000;
    evtimer_add(timer_event, &timer_interval);

    /* Initialize Tx message queues */
    mapTxQueues = init_tx_queues(group_list, multicast_list);

    udp_write_threads.emplace_back(boost::bind(&TraceThread<boost::function<void ()> >, "udpwrite", &ThreadRunWriteEventLoop));

    /* Add persistent connections to pre-defined udpnodes or trustedudpnodes */
    AddConfAddedConnections();

    /* One-way multicast connections */
    for (const auto& multicastNode : mapMulticastNodes) {
        OpenMulticastConnection(std::get<0>(multicastNode.first),
                                multicastNode.second.tx,
                                multicastNode.second.group,
                                multicastNode.second.trusted);
    }

    /* Multicast transmission threads */
    LaunchMulticastBackfillThreads();

    BlockRecvInit();

    udp_read_thread.reset(new std::thread(&TraceThread<void (*)()>, "udpread", &ThreadRunReadEventLoop));

    return true;
}

void StopUDPConnections() {
    if (!udp_read_thread)
        return;

    event_base_loopbreak(event_base_read);
    udp_read_thread->join();
    udp_read_thread.reset();

    BlockRecvShutdown();

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    for (auto const& s : mapUDPNodes) {
        if (s.second.connection.connection_type == UDP_CONNECTION_TYPE_NORMAL)
            SendMessage(msg, sizeof(UDPMessageHeader), true, s);
    }
    mapUDPNodes.clear();

    send_messages_flush_and_break();

    for (std::thread& t : udp_write_threads)
        t.join();
    udp_write_threads.clear();

    for (std::thread& t : mcast_tx_threads)
        t.join();
    mcast_tx_threads.clear();

    CloseSocketsAndReadEvents();

    event_free(timer_event);
    event_base_free(event_base_read);
}



/**
 * Network handling follows
 */

static std::map<CService, UDPConnectionState>::iterator silent_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    return mapUDPNodes.erase(it);
}

static std::map<CService, UDPConnectionState>::iterator send_and_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    SendMessage(msg, sizeof(UDPMessageHeader), false, *it);

    int64_t now = GetTimeMillis();
    while (!nodesToRepeatDisconnect.insert(std::make_pair(now + 1000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second)
        now++;
    assert(nodesToRepeatDisconnect.insert(std::make_pair(now + 10000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second);

    return silent_disconnect(it);
}

void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it) {
    send_and_disconnect(it);
}

static void read_socket_func(evutil_socket_t fd, short event, void* arg) {
    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());

    UDPMessage msg{};
    /* We will place the incoming UDP message payload into `msg`. However, not
     * necessarily the incoming payload will fill the entire `UDPMessage`
     * structure. Hence, zero-initialize `msg` here. */
    struct sockaddr_in6 remoteaddr;
    socklen_t remoteaddrlen = sizeof(remoteaddr);

    ssize_t res = recvfrom(fd, &msg, sizeof(msg), MSG_DONTWAIT, (sockaddr*)&remoteaddr, &remoteaddrlen);
    if (res < 0) {
        int err = errno;
        LogPrintf("UDP: Error reading from socket: %d (%s)!\n", err, strerror(err));
        return;
    }
    assert(remoteaddrlen == sizeof(remoteaddr));
    CService c_remoteaddr(remoteaddr);

    if (size_t(res) < sizeof(UDPMessageHeader) || size_t(res) >= sizeof(UDPMessage))
        return;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    /* Is this coming from a multicast Tx node and through a multicast Rx
     * socket? */
    bool from_mcast_tx = false;
    std::map<std::tuple<CService, int, uint16_t>, UDPMulticastInfo>::iterator itm;
    for (itm = mapMulticastNodes.begin(); itm != mapMulticastNodes.end(); ++itm) {
        if ((CNetAddr)c_remoteaddr == (CNetAddr)(std::get<0>(itm->first))) {
            if (fd == itm->second.fd) {
                from_mcast_tx = true;
                break;
            }
        }
    }

    /* If receiving from a multicast service, find node by IP only and not with
     * the address brought by `recvfrom`, which includes the source port. This
     * is because the source port of multicast Tx nodes can be random. */
    std::map<CService, UDPConnectionState>::iterator it;
    if (from_mcast_tx) {
        const CService& mcasttx_addr = std::get<0>(itm->first);
        it = mapUDPNodes.find(mcasttx_addr);
    } else
        it = mapUDPNodes.find(c_remoteaddr);

    if (it == mapUDPNodes.end())
        return;
    if (!CheckChecksum(it->second.connection.local_magic, msg, res))
        return;

    UDPConnectionState& state = it->second;

    const uint8_t msg_type_masked = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK);

    /* Handle multicast msgs first (no need to check connection state) */
    if (state.connection.udp_mode == udp_mode_t::multicast)
    {
        if (itm == mapMulticastNodes.end()) {
            LogPrintf("Couldn't find multicast node\n");
            return;
        }
        const UDPMulticastInfo& mcast_info = itm->second;

        if (msg_type_masked == MSG_TYPE_BLOCK_HEADER ||
            msg_type_masked == MSG_TYPE_BLOCK_CONTENTS ||
            msg_type_masked == MSG_TYPE_TX_CONTENTS) {
            if (!HandleBlockTxMessage(msg, sizeof(UDPMessage) - 1, it->first, it->second, start, fd))
                send_and_disconnect(it);
            else {
                if (LogAcceptCategory(BCLog::UDPMCAST)) {
                    mcast_info.stats.rcvdBytes += sizeof(UDPMessage) - 1;
                    auto now = std::chrono::steady_clock::now();
                    double timeDeltaMillis = to_millis_double(now - mcast_info.stats.lastRxTime);
                    if (timeDeltaMillis > 1000*mcastStatPrintInterval) {
                        LogPrint(BCLog::UDPMCAST, "UDP multicast group %d: Average bit rate %7.2f Mbit/sec (%s)\n",
                                 mcast_info.group,
                                 (double)mcast_info.stats.rcvdBytes*8/(1000*timeDeltaMillis),
                                 mcast_info.groupname);
                        mcast_info.stats.lastRxTime = now;
                        mcast_info.stats.rcvdBytes = 0;
                    }
                }
            }
        } else
            LogPrintf("UDP: Unexpected message from %s!\n", it->first.ToString());

        return;
    }

    state.lastRecvTime = GetTimeMillis();
    if (msg_type_masked == MSG_TYPE_SYN) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized SYN message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        state.protocolVersion = le64toh(msg.msg.longint);
        if (PROTOCOL_VERSION_MIN(state.protocolVersion) > PROTOCOL_VERSION_CUR(UDP_PROTOCOL_VERSION)) {
            LogPrintf("UDP: Got min protocol version we didnt understand (%u:%u) from %s\n", PROTOCOL_VERSION_MIN(state.protocolVersion), PROTOCOL_VERSION_CUR(state.protocolVersion), it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        if (!(state.state & STATE_GOT_SYN))
            state.state |= STATE_GOT_SYN;
    } else if (msg_type_masked == MSG_TYPE_KEEPALIVE) {
        if (res != sizeof(UDPMessageHeader)) {
            LogPrintf("UDP: Got invalidly-sized KEEPALIVE message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }
        if ((state.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
            LogPrint(BCLog::UDPNET, "UDP: Successfully connected to %s!\n", it->first.ToString());

        // If we get a SYNACK without a SYN, that probably means we were restarted, but the other side wasn't
        // ...this means the other side thinks we're fully connected, so just switch to that mode
        state.state |= STATE_GOT_SYN_ACK | STATE_GOT_SYN;
    } else if (msg_type_masked == MSG_TYPE_DISCONNECT) {
        LogPrintf("UDP: Got disconnect message from %s\n", it->first.ToString());
        silent_disconnect(it);
        return;
    }

    if (!(state.state & STATE_INIT_COMPLETE))
        return;

    if (msg_type_masked == MSG_TYPE_BLOCK_HEADER || msg_type_masked == MSG_TYPE_BLOCK_CONTENTS) {
        if (!HandleBlockTxMessage(msg, res, it->first, it->second, start, fd)) {
            send_and_disconnect(it);
            return;
        }
    } else if (msg_type_masked == MSG_TYPE_TX_CONTENTS) {
        LogPrintf("UDP: Got tx message over the wire from %s, this isn't supposed to happen!\n", it->first.ToString());
        /* NOTE Only the multicast service sends tx messages. */
        send_and_disconnect(it);
        return;
    } else if (msg_type_masked == MSG_TYPE_PING) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PING message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        msg.header.msg_type = MSG_TYPE_PONG;
        SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, *it);
    } else if (msg_type_masked == MSG_TYPE_PONG) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PONG message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        uint64_t nonce = le64toh(msg.msg.longint);
        std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.find(nonce);
        if (nonceit == state.ping_times.end()) // Possibly duplicated packet
            LogPrintf("UDP: Got PONG message without PING from %s\n", it->first.ToString());
        else {
            double rtt = (GetTimeMicros() - nonceit->second) / 1000.0;
            LogPrintf("UDP: RTT to %s is %lf ms\n", it->first.ToString(), rtt);
            state.ping_times.erase(nonceit);
            state.last_pings[state.last_ping_location] = rtt;
            state.last_ping_location = (state.last_ping_location + 1) % (sizeof(state.last_pings) / sizeof(double));
        }
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finish(std::chrono::steady_clock::now());
        if (to_millis_double(finish - start) > 1)
            LogPrintf("UDP: Packet took %lf ms to process\n", to_millis_double(finish - start));
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info);
static void timer_func(evutil_socket_t fd, short event, void* arg) {
    ProcessDownloadTimerEvents();

    UDPMessage msg;
    const int64_t now = GetTimeMillis();

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    {
        std::map<int64_t, std::tuple<CService, uint64_t, size_t> >::iterator itend = nodesToRepeatDisconnect.upper_bound(now);
        for (std::map<int64_t, std::tuple<CService, uint64_t, size_t> >::const_iterator it = nodesToRepeatDisconnect.begin(); it != itend; it++) {
            msg.header.msg_type = MSG_TYPE_DISCONNECT;
            SendMessage(msg, sizeof(UDPMessageHeader), false, std::get<0>(it->second), std::get<1>(it->second), std::get<2>(it->second));
        }
        nodesToRepeatDisconnect.erase(nodesToRepeatDisconnect.begin(), itend);
    }

    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end();) {

        if (it->second.connection.connection_type != UDP_CONNECTION_TYPE_NORMAL) {
            it++;
            continue;
        }

        UDPConnectionState& state = it->second;

        int64_t origLastSendTime = state.lastSendTime;

        if (state.lastRecvTime < now - 1000 * 60 * 10) {
            LogPrint(BCLog::UDPNET, "UDP: Peer %s timed out\n", it->first.ToString());
            it = send_and_disconnect(it); // Removes it from mapUDPNodes
            continue;
        }

        if (!(state.state & STATE_GOT_SYN_ACK) && origLastSendTime < now - 1000) {
            msg.header.msg_type = MSG_TYPE_SYN;
            msg.msg.longint = htole64(UDP_PROTOCOL_VERSION);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, *it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_GOT_SYN) && origLastSendTime < now - 1000 * ((state.state & STATE_GOT_SYN_ACK) ? 10 : 1)) {
            msg.header.msg_type = MSG_TYPE_KEEPALIVE;
            SendMessage(msg, sizeof(UDPMessageHeader), false, *it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_INIT_COMPLETE) == STATE_INIT_COMPLETE && state.lastPingTime < now - 1000 * 60 * 15) {
            uint64_t pingnonce = GetRand(std::numeric_limits<uint64_t>::max());
            msg.header.msg_type = MSG_TYPE_PING;
            msg.msg.longint = htole64(pingnonce);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, *it);
            state.ping_times[pingnonce] = GetTimeMicros();
            state.lastPingTime = now;
        }

        for (std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.begin(); nonceit != state.ping_times.end();) {
            if (nonceit->second < (now - 5000) * 1000)
                nonceit = state.ping_times.erase(nonceit);
            else
                nonceit++;
        }

        it++;
    }

    for (const auto& conn : mapPersistentNodes) {
        if (!mapUDPNodes.count(conn.first)) {
            bool fWaitingOnDisconnect = false;
            for (const auto& repeatNode : nodesToRepeatDisconnect) {
                if (std::get<0>(repeatNode.second) == conn.first)
                    fWaitingOnDisconnect = true;
            }
            if (fWaitingOnDisconnect)
                continue;

            OpenUDPConnectionTo(conn.first, conn.second);
        }
    }
}

static inline void SendMessage(const UDPMessage& msg, const unsigned int length, PerGroupMessageQueue& queue, PendingMessagesBuff& buff, const CService& service, const uint64_t magic) {
    std::unique_lock<std::mutex> lock(send_messages_mutex);
    while (!send_messages_break &&
           buff.nextPendingMessage == ((buff.nextUndefinedMessage + 1) % PENDING_MESSAGES_BUFF_SIZE)) {
        lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        lock.lock();
    }

    if (send_messages_break) return;

    const uint16_t next_undefined_message_cache = buff.nextUndefinedMessage;
    const uint16_t next_pending_message_cache = buff.nextPendingMessage;

    std::tuple<CService, UDPMessage, unsigned int, uint64_t>& new_msg = buff.messagesPendingRingBuff[next_undefined_message_cache];
    std::get<0>(new_msg) = service;
    memcpy(&std::get<1>(new_msg), &msg, length);
    std::get<2>(new_msg) = length;
    std::get<3>(new_msg) = magic;

    bool need_notify = next_undefined_message_cache == next_pending_message_cache;
    buff.nextUndefinedMessage = (next_undefined_message_cache + 1) % PENDING_MESSAGES_BUFF_SIZE;

    lock.unlock();
    if (need_notify)
        send_messages_wake_cv.notify_all();
}

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const CService& service, const uint64_t magic, size_t group) {
    assert(length <= sizeof(UDPMessage));
    assert(mapTxQueues.count(group));
    PerGroupMessageQueue& queue = mapTxQueues[group];
    PendingMessagesBuff& buff   = high_prio ? queue.buffs[0] : queue.buffs[1];
    SendMessage(msg, length, queue, buff, service, magic);
}

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const std::pair<const CService, UDPConnectionState>& node) {
    SendMessage(msg, length, high_prio, node.first, node.second.connection.remote_magic, node.second.connection.group);
}

static inline bool fill_cache(const std::chrono::steady_clock::time_point& now) {
    bool have_work = false;

    for (auto& q : mapTxQueues) {
        PerGroupMessageQueue& queue = q.second;
        PerQueueSendState& state    = queue.state;

        if (state.next_send > now)
            continue;

        state.buff_state = queue.NextBuff();
        if (state.buff_state.buff_id != -1) {
            have_work = true;
            break;
        }
    }
    return have_work;
}

static const int ip_udp_header_size = 8 + 20; // Min IPv4 header + UDP header

static void do_send_messages() {
#ifndef WIN32
    {
        struct sched_param sched{sched_get_priority_max(SCHED_RR)};
        int res = pthread_setschedparam(pthread_self(), SCHED_RR, &sched);
        LogPrintf("UDP: %s write thread priority to SCHED_RR%s\n", !res ? "Set" : "Was unable to set", !res ? "" : (res == EPERM ? " (permission denied)" : " (other error)"));
        if (res) {
            res = nice(-20);
            errno = 0;
            LogPrintf("UDP: %s write thread nice value to %d%s\n", !errno ? "Set" : "Was unable to set", res, !errno ? "" : (errno == EPERM ? " (permission denied)" : " (other error)"));
        }
    }
#endif

    /* Initialize state of Tx queues */
    const std::chrono::steady_clock::time_point t_now(std::chrono::steady_clock::now());
    for (auto& q : mapTxQueues) {
        q.second.state.buff_state = {-1, 0, 0};
        q.second.state.next_send  = t_now;
        q.second.state.last_send  = t_now;
    }

    while (true) {
        if (send_messages_break)
            return;
        std::chrono::steady_clock::time_point sleep_until(std::chrono::steady_clock::now() + std::chrono::minutes(60));

        /* Iterate over Tx queues and schedule transmissions */
        for (auto& q : mapTxQueues) {
            PerGroupMessageQueue& queue   = q.second;
            PerQueueSendState& send_state = queue.state;
            const size_t group            = q.first;
            const std::chrono::steady_clock::time_point t_now(std::chrono::steady_clock::now());

            if (send_state.next_send > t_now) {
                sleep_until = std::min(sleep_until, send_state.next_send);
                continue;
            }

            /* Search a higher priority non-empty buffer if... */
            if (send_state.buff_state.buff_id != 0 || // we are not currently in the highest priority buffer
                send_state.buff_state.nextPendingMessage == send_state.buff_state.nextUndefinedMessage) { // ...or we're out of known messages
                send_state.buff_state = queue.NextBuff();
            }

            if (send_state.buff_state.buff_id == -1)
                continue;

            PendingMessagesBuff* buff = &queue.buffs[send_state.buff_state.buff_id];
            std::tuple<CService, UDPMessage, unsigned int, uint64_t>& msg = buff->messagesPendingRingBuff[send_state.buff_state.nextPendingMessage];
            queue.byte_quota += queue.target_bytes_per_sec * to_seconds(t_now - send_state.last_send);

            /* Don't let this Tx group hold the link for too long */
            if (queue.byte_quota > queue.max_byte_quota_per_turn)
                queue.byte_quota = queue.max_byte_quota_per_turn;

            while (queue.byte_quota > (std::get<2>(msg) + ip_udp_header_size) && send_state.buff_state.buff_id != -1) {
                if (queue.multicast) {
                    assert((std::get<1>(msg).header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER ||
                           (std::get<1>(msg).header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS ||
                           (std::get<1>(msg).header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_TX_CONTENTS);
                }

                FillChecksum(std::get<3>(msg), std::get<1>(msg), std::get<2>(msg));

                sockaddr_storage ss = {};
                socklen_t addrlen;

                if (std::get<0>(msg).IsIPv6()) {
                    sockaddr_in6 *remoteaddr = (sockaddr_in6 *) &ss;
                    remoteaddr->sin6_family = AF_INET6;
                    assert(std::get<0>(msg).GetIn6Addr(&remoteaddr->sin6_addr));
                    remoteaddr->sin6_port = htons(std::get<0>(msg).GetPort());
                    addrlen = sizeof(sockaddr_in6);
                } else {
                    sockaddr_in *remoteaddr = (sockaddr_in *) &ss;
                    remoteaddr->sin_family = AF_INET;
                    assert(std::get<0>(msg).GetInAddr(&remoteaddr->sin_addr));
                    remoteaddr->sin_port = htons(std::get<0>(msg).GetPort());
                    addrlen = sizeof(sockaddr_in);
                }

                if (sendto(udp_socks[group], &std::get<1>(msg), std::get<2>(msg), 0, (sockaddr *) &ss, addrlen) != std::get<2>(msg)) {
                    //TODO: Handle?
                    LogPrintf("UDP: sendto to group %d failed: %s\n",
                              group, strerror(errno));
                }

                queue.byte_quota -= std::get<2>(msg) + ip_udp_header_size;

                send_state.buff_state.nextPendingMessage = (send_state.buff_state.nextPendingMessage + 1) % PENDING_MESSAGES_BUFF_SIZE;
                if (send_state.buff_state.nextPendingMessage == send_state.buff_state.nextUndefinedMessage) {
                    buff->nextPendingMessage = send_state.buff_state.nextPendingMessage;
                    send_state.buff_state = queue.NextBuff();
                    if (send_state.buff_state.buff_id != -1)
                        buff = &queue.buffs[send_state.buff_state.buff_id];
                }

                msg = buff->messagesPendingRingBuff[send_state.buff_state.nextPendingMessage];
            }

            send_state.last_send  = send_state.next_send;
            send_state.next_send += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::duration<double>(max_tx_group_turn_duration));

            if (send_state.buff_state.buff_id != -1)
                buff->nextPendingMessage = send_state.buff_state.nextPendingMessage;

            sleep_until = std::min(sleep_until, send_state.next_send);
        }

        std::chrono::steady_clock::time_point end(std::chrono::steady_clock::now());
        if (sleep_until > end) { // No need to be aggressive here, fill_cache is useful to speed up per-queue loop anyway
            if (fill_cache(end))
                continue;
            std::unique_lock<std::mutex> lock(send_messages_mutex);
            if (!fill_cache(end))
                send_messages_wake_cv.wait_until(lock, sleep_until);
        }
    }
}

struct backfill_block {
    std::vector<UDPMessage> msgs;
    mutable size_t idx = 0; // index of next message to be transmitted
};

static void MulticastBackfillThread(const CService& mcastNode,
                                    const UDPMulticastInfo *info) {
    /* Start only after the initial sync */
    while (::ChainstateActive().IsInitialBlockDownload() && !send_messages_break)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // if IsInitialBlockDownload() is false, chainActive.Tip()->pprev will
    // return nullptr and trip the assert below
    if (send_messages_break) return;

    const int backfill_depth = info->depth;

    const CBlockIndex *lastBlock;
    {
        LOCK(cs_main);
        lastBlock = ::ChainActive().Tip();
        assert(lastBlock);
    }

    /* Debug options */
    const bool debugMcast = LogAcceptCategory(BCLog::UDPMCAST);
    std::chrono::steady_clock::time_point t_cycle_start = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point t_last_win_stats = std::chrono::steady_clock::now();
    const int window_stats_interval = 60; // in seconds

    auto it = mapTxQueues.find(info->group);
    assert(it != mapTxQueues.end());
    PerGroupMessageQueue& queue = it->second;

    std::map<int, backfill_block> block_window;
    const size_t target_window_size = std::max(info->interleave_size/FEC_CHUNK_SIZE, 1);

    while (!send_messages_break) {
        /* Fill FEC chunk interleaving window */
        while ((block_window.size() < target_window_size) && (!send_messages_break)) {
            /* Height of block to be inserted on the block window */
            int height;
            bool wrapped_around = false;
            {
                LOCK(cs_main);
                height = lastBlock->nHeight + 1;
                const int chain_height = ::ChainActive().Height();

                if ((height < chain_height - backfill_depth + 1) && (backfill_depth > 0))
                    height = chain_height - backfill_depth + 1;
                else if (height > chain_height) {
                    if (backfill_depth == 0)
                        height = 0;
                    else
                        height = chain_height - backfill_depth + 1;
                    wrapped_around = true;
                }

                lastBlock = ::ChainActive()[height];
            }

            if (debugMcast && wrapped_around) {
                std::chrono::steady_clock::time_point t_cycle_end(std::chrono::steady_clock::now());
                std::chrono::duration<float> backfill_cycle_duration = t_cycle_end - t_cycle_start;
                t_cycle_start = t_cycle_end;
                LogPrint(BCLog::UDPMCAST, "UDP: Multicast Tx %lu-%lu - cycle finished in %f secs\n",
                         info->physical_idx, info->logical_idx, backfill_cycle_duration.count());
            }

            /* Fetch block from disk and generate its FEC chunks */
            CBlock block;
            assert(ReadBlockFromDisk(block, lastBlock, Params().GetConsensus()));
            const auto res = block_window.insert(std::make_pair(height, backfill_block()));
            if (!res.second)
                throw std::runtime_error("Failed to insert new block on backfill window");
            const auto block_it = res.first;
            UDPFillMessagesFromBlock(block, block_it->second.msgs, height);
            const uint256 block_hash(block.GetHash());

            LogPrint(BCLog::FEC, "UDP: Multicast Tx %lu-%lu - fill block %s (%20lu) - height %7d - %5d chunks\n",
                     info->physical_idx, info->logical_idx,
                     block_hash.ToString(), block_hash.GetUint64(0),
                     height, block_it->second.msgs.size());
        }

        /* Send window of interleaved chunks */
        for (const auto& b : block_window) {
            if (send_messages_break)
                break;
            assert(b.second.idx < b.second.msgs.size());
            const UDPMessage& msg = b.second.msgs[b.second.idx];
            b.second.idx++;
            SendMessage(msg, sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH, queue, queue.buffs[3], mcastNode, multicast_checksum_magic);
        }

        /* Print some info regarding blocks that are currently in the
         * block-interleaving window */
        if (debugMcast && target_window_size > 1) {
            const auto t_now = std::chrono::steady_clock::now();
            const double timeDeltaMillis = to_millis_double(t_now - t_last_win_stats);
            if (timeDeltaMillis > 1000*window_stats_interval) {
                int min_height   = std::numeric_limits<int>::max();
                int max_height   = 0;
                size_t max_n_chunks = 0;
                int height_largest_block;
                const backfill_block* b_min_height = nullptr;
                const backfill_block* b_max_height = nullptr;
                const backfill_block* b_largest    = nullptr;
                for (const auto& b : block_window) {
                    if (b.first < min_height) {
                        min_height   = b.first;
                        b_min_height = &b.second;
                    }
                    if (b.first > max_height) {
                        max_height   = b.first;
                        b_max_height = &b.second;
                    }
                    if (b.second.msgs.size() > max_n_chunks) {
                        max_n_chunks         = b.second.msgs.size();
                        height_largest_block = b.first;
                        b_largest            = &b.second;
                    }
                }
                assert(b_min_height != nullptr);
                assert(b_max_height != nullptr);
                assert(b_largest != nullptr);
                LogPrint(BCLog::UDPMCAST,
                         "UDP: Multicast Tx %lu-%lu - Block Window:\n"
                         "\t\tMin Height:    %7d - Sent %4d / %4d chunks\n"
                         "\t\tMax Height:    %7d - Sent %4d / %4d chunks\n"
                         "\t\tLargest Block: %7d - Sent %4d / %4d chunks\n",
                         info->physical_idx, info->logical_idx,
                         min_height, b_min_height->idx, b_min_height->msgs.size(),
                         max_height, b_max_height->idx, b_max_height->msgs.size(),
                         height_largest_block, b_largest->idx, b_largest->msgs.size()
                    );
                t_last_win_stats = t_now;
            }
        }

        /* Cleanup blocks that have been fully transmitted */
        for (auto it = block_window.cbegin(); it != block_window.cend();) {
            if (it->second.idx == it->second.msgs.size())
                it = block_window.erase(it);
            else
                ++it;
        }
    }
}

static void MulticastTxnThread(const CService& mcastNode,
                               const UDPMulticastInfo *info) {
    assert(info->txn_per_sec > 0);
    double txn_per_sec = (double) info->txn_per_sec;

    /* Start only after the initial sync */
    while (::ChainstateActive().IsInitialBlockDownload() && !send_messages_break)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // if IsInitialBlockDownload() is false, chainActive.Tip()->pprev will
    // return nullptr and trip the assert below
    if (send_messages_break) return;

    /* Debug options */
    const bool debugMcast = LogAcceptCategory(BCLog::UDPMCAST);
    const int stats_interval = 10;
    int n_sent_txns = 0;
    std::chrono::steady_clock::time_point last_print = std::chrono::steady_clock::now();

    /* Use a bloom filter to keep track of txns already sent */
    boost::optional<CRollingBloomFilter> sent_txn_bloom;
    sent_txn_bloom.emplace(500000, 0.001); // Hold 500k (~24*6 blocks of txn) txn

    auto it = mapTxQueues.find(info->group);
    assert(it != mapTxQueues.end());
    PerGroupMessageQueue& queue = it->second;

    /* The txn transmission quota is based on the elapsed interval since
     * last time txns were sent, which is the "txn quota of seconds". */
    double txn_quota_sec = 0;
    int txn_tx_quota = 0;
    std::chrono::steady_clock::time_point last_tx_time = std::chrono::steady_clock::now();

    while (!send_messages_break) {
        /* Txn transmission quota (number of txns to transmit now) */
        std::chrono::steady_clock::time_point const now = std::chrono::steady_clock::now();
        txn_quota_sec += to_seconds(now - last_tx_time);
        last_tx_time = now;
        txn_tx_quota = txn_quota_sec * txn_per_sec;

        if (txn_tx_quota > 0) {
            /* We will send txns now, so we must remove the corresponding
             * interval from the quota of seconds. Any residual interval will be
             * left in the quota. This way, we avoid roundoff errors. */
            txn_quota_sec -= txn_tx_quota / txn_per_sec;

            std::vector<CTransactionRef> txn_to_send;
            txn_to_send.reserve(txn_tx_quota);
            {
                std::set<uint256> txids_to_send;
                LOCK(mempool.cs);
                for (const auto& iter : mempool.mapTx.get<ancestor_score>()) {
                    if (txn_to_send.size() >= (unsigned int)txn_tx_quota)
                        break;
                    if (txids_to_send.count(iter.GetTx().GetHash()) || sent_txn_bloom->contains(iter.GetTx().GetHash()))
                        continue;

                    std::vector<CTransactionRef> to_add{iter.GetSharedTx()};
                    while (!to_add.empty()) {
                        bool has_dep = false;
                        for (const CTxIn& txin : to_add.back()->vin) {
                            CTxMemPool::txiter init = mempool.mapTx.find(txin.prevout.hash);
                            if (init != mempool.mapTx.end() && !txids_to_send.count(txin.prevout.hash)) {
                                to_add.emplace_back(init->GetSharedTx());
                                has_dep = true;
                            }
                        }
                        if (!has_dep) {
                            if (txids_to_send.insert(to_add.back()->GetHash()).second) {
                                sent_txn_bloom->insert(to_add.back()->GetHash());
                                txn_to_send.emplace_back(std::move(to_add.back()));
                            }
                            to_add.pop_back();
                        }
                    }
                }
            }

            for (const CTransactionRef& tx : txn_to_send) {
                std::vector<std::pair<UDPMessage, size_t>> msgs;
                UDPFillMessagesFromTx(*tx, msgs);
                for (const auto& msg_info : msgs) {
                    const UDPMessage& msg = msg_info.first;
                    const size_t msg_size = msg_info.second;
                    SendMessage(msg, sizeof(UDPMessageHeader) + udp_blk_msg_header_size + msg_size, queue, queue.buffs[2], mcastNode, multicast_checksum_magic);
                }

                if (debugMcast) {
                    n_sent_txns++;
                    const auto now = std::chrono::steady_clock::now();
                    const double timeDeltaMillis = to_millis_double(now - last_print);
                    if (timeDeltaMillis > 1000*stats_interval) {
                        LogPrint(BCLog::UDPMCAST,
                                 "UDP: Multicast Tx %lu-%lu - sent %4d txns "
                                 "in %5.2f secs (current quota: %5.2f)\n",
                                 info->physical_idx, info->logical_idx,
                                 n_sent_txns, timeDeltaMillis/1000,
                                 (txn_quota_sec * txn_per_sec));
                        last_print = now;
                        n_sent_txns = 0;
                    }
                }
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

static void LaunchMulticastBackfillThreads() {
    for (const auto& node : mapMulticastNodes) {
        auto& info = node.second;
        if (info.tx) {
            mcast_tx_threads.emplace_back([&info, &node] {
                    char name[50];
                    sprintf(name, "udpblkbackfill %d-%d", info.physical_idx,
                            info.logical_idx);
                    TraceThread(
                        name,
                        std::bind(MulticastBackfillThread,
                                  std::get<0>(node.first), &info)
                        );
                });

            if (info.txn_per_sec > 0) {
                mcast_tx_threads.emplace_back([&info, &node] {
                        char name[50];
                        sprintf(name, "udptxnbackfill %d-%d", info.physical_idx,
                                info.logical_idx);
                        TraceThread(
                            name,
                            std::bind(MulticastTxnThread,
                                      std::get<0>(node.first), &info)
                            );
                    });
            }
        }
    }
}

static std::map<size_t, PerGroupMessageQueue> init_tx_queues(const std::vector<std::pair<unsigned short, uint64_t> >& group_list,
                                                             const std::vector<UDPMulticastInfo>& multicast_list) {
    std::map<size_t, PerGroupMessageQueue> mapQueues; // map group number to group queue

    /* Each unicast UDP groups has one queue, defined in order */
    for (size_t group = 0; group < group_list.size(); group++) {
        auto res = mapQueues.emplace(std::piecewise_construct,
                                     std::forward_as_tuple(group),
                                     std::forward_as_tuple());
        LogPrintf("UDP: Set bw for group %d: %d Mbps\n", group, group_list[group].second);
        assert(res.second);
        res.first->second.bw        = group_list[group].second;
        res.first->second.multicast = false;
    }

    /* Multicast Rx instances don't have any Tx queue. Only multicast Tx
     * instances do. */
    for (const auto& info : multicast_list) {
        if (info.tx) {
            assert(info.bw > 0);
            LogPrintf("UDP: Set bw for group %d: %d bps\n", info.group, info.bw);
            auto res = mapQueues.emplace(std::piecewise_construct,
                                         std::forward_as_tuple(info.group),
                                         std::forward_as_tuple());
            assert(res.second);
            res.first->second.bw        = info.bw;
            res.first->second.multicast = true;
        }
    }

    /* Throughput settings of each Tx group
     *
     * - On average, the transmission loop will try to respect
     *   `target_bytes_per_sec` bytes/sec for each Tx group. This will be the
     *   sum rate of all 3 message queues of the group.
     *
     * - Only one Tx group can be transmitting at a time and, hence, Tx groups
     *   take turns. On each turn, there is a limit for the number of bytes the
     *   Tx group can transmit. This is just so that other queues don't wait too
     *   long for their turn. The limit is proportional to the groups's
     *   throughput and there is some margin such that the residual quota from
     *   the previous turn is not lost due to capping.
     *
     * NOTE: -udpport sets bw in Mbps, while -udpmulticasttx sets in bps. */
    for (auto it = mapQueues.begin(); it != mapQueues.end(); it++) {
        double& target_bytes_per_sec       = it->second.target_bytes_per_sec;
        target_bytes_per_sec               = it->second.bw * (it->second.multicast ? 1 : 1024 * 1024) / 8;
        const double cap_margin            = sizeof(UDPMessage) + ip_udp_header_size - 1;
        it->second.max_byte_quota_per_turn = (target_bytes_per_sec * max_tx_group_turn_duration) + cap_margin;
    }

    return mapQueues;
}

static void send_messages_flush_and_break() {
    send_messages_break = true;
    send_messages_wake_cv.notify_all();
}

static UDPMulticastInfo ParseUDPMulticastInfo(const std::string& s, const bool tx) {
    UDPMulticastInfo info{};
    info.port = 0; // use port == 0 to infer error

    const size_t if_end = s.find(',');
    if (if_end == std::string::npos) {
        LogPrintf("Failed to parse -udpmulticast option, net interface not set\n");
        return info;
    }
    strncpy(info.ifname, s.substr(0, if_end).c_str(), IFNAMSIZ);

    const size_t mcastaddr_end = s.find(',', if_end + 1);
    if (mcastaddr_end == std::string::npos) {
        LogPrintf("Failed to parse -udpmulticast option, missing required arguments\n");
        return info;
    }

    int port;
    std::string ip;
    const std::string mcast_ip_port = s.substr(if_end + 1, mcastaddr_end - if_end - 1);
    SplitHostPort(mcast_ip_port, port, ip);
    if (port != (unsigned short)port || port == 0) {
        LogPrintf("Failed to parse -udpmulticast option, invalid port\n");
        return info;
    }
    strncpy(info.mcast_ip, ip.c_str(), INET_ADDRSTRLEN);

    info.tx         = tx;

    /* Defaults */
    info.groupname       = "";
    info.ttl             = 3;
    info.bw              = 0;
    info.logical_idx     = 0; // default for multicast Rx, overriden for Tx
    info.depth           = 144;
    info.interleave_size = 0; // default is to disable interleaving
    info.dscp            = 0; // IPv4 DSCP used for multicast Tx
    info.trusted         = false;

    if (info.tx) {
        const size_t bw_end = s.find(',', mcastaddr_end + 1);

        if (bw_end == std::string::npos) {
            LogPrintf("Failed to parse -udpmulticasttx option, missing required arguments\n");
            return info;
        }
        info.bw  = atoi64(s.substr(mcastaddr_end + 1, bw_end - mcastaddr_end - 1));

        const size_t txn_per_sec_end = s.find(',', bw_end + 1);
        if (txn_per_sec_end == std::string::npos)
            info.txn_per_sec = atoi64(s.substr(bw_end + 1));
        else {
            info.txn_per_sec = atoi64(s.substr(bw_end + 1, txn_per_sec_end - bw_end - 1));

            const size_t ttl_end = s.find(',', txn_per_sec_end + 1);
            if (ttl_end == std::string::npos) {
                info.ttl = atoi(s.substr(txn_per_sec_end + 1));
            } else {
                info.ttl   = atoi(s.substr(txn_per_sec_end + 1, ttl_end - txn_per_sec_end - 1));

                const size_t depth_end = s.find(',', ttl_end + 1);
                if (depth_end == std::string::npos) {
                    info.depth = atoi(s.substr(ttl_end + 1));
                } else {
                    info.depth = atoi(s.substr(ttl_end + 1, depth_end - ttl_end - 1));

                    const size_t dscp_end = s.find(',', depth_end + 1);
                    if (dscp_end == std::string::npos) {
                        info.dscp  = atoi(s.substr(depth_end + 1));
                    } else {
                        info.dscp  = atoi(s.substr(depth_end + 1, dscp_end - depth_end - 1));
                        info.interleave_size = atoi(s.substr(dscp_end + 1)) * info.bw / 8;
                    }
                }
            }
        }

        if (info.depth < 0) {
            LogPrintf("Failed to parse -udpmulticasttx option, depth must be >= 0\n");
            return info;
        }

        if (info.bw == 0) {
            LogPrintf("Failed to parse -udpmulticasttx option, bw must be non-zero\n");
            return info;
        }
    } else {
        const size_t tx_ip_end = s.find(',', mcastaddr_end + 1);
        std::string tx_ip;

        if (tx_ip_end == std::string::npos) {
            LogPrintf("Failed to parse -udpmulticast option, missing required arguments\n");
            return info;
        }

        tx_ip = s.substr(mcastaddr_end + 1, tx_ip_end - mcastaddr_end - 1);

        const size_t trusted_end = s.find(',', tx_ip_end + 1);

        if (trusted_end == std::string::npos)
            info.trusted   = (bool) atoi64(s.substr(tx_ip_end + 1));
        else {
            info.trusted   = (bool) atoi64(s.substr(tx_ip_end + 1, trusted_end - tx_ip_end - 1));
            info.groupname = s.substr(trusted_end + 1);
        }

        if (tx_ip.empty()) {
            LogPrintf("Failed to parse -udpmulticast option, source (tx) IP empty\n");
            return info;
        }
        strncpy(info.tx_ip, tx_ip.c_str(), INET_ADDRSTRLEN);
    }

    info.port = port; /* set non-zero port if successful */

    return info;
}

static std::vector<UDPMulticastInfo> GetUDPMulticastInfo()
{
    if (!gArgs.IsArgSet("-udpmulticast") && !gArgs.IsArgSet("-udpmulticasttx"))
        return std::vector<UDPMulticastInfo>();

    std::vector<UDPMulticastInfo> v;

    for (const std::string& s : gArgs.GetArgs("-udpmulticast")) {
        v.push_back(ParseUDPMulticastInfo(s, false));
        if (v.back().port == 0)
            return std::vector<UDPMulticastInfo>();
    }

    for (const std::string& s : gArgs.GetArgs("-udpmulticasttx")) {
        v.push_back(ParseUDPMulticastInfo(s, true));
        if (v.back().port == 0)
            return std::vector<UDPMulticastInfo>();
    }

    return v;
}

static void OpenMulticastConnection(const CService& service, bool multicast_tx, size_t group, bool trusted) {
    OpenPersistentUDPConnectionTo(service, multicast_magic, multicast_magic, trusted,
                                  multicast_tx ? UDP_CONNECTION_TYPE_OUTBOUND_ONLY : UDP_CONNECTION_TYPE_INBOUND_ONLY,
                                  group, udp_mode_t::multicast);
}

/**
 * Public API follows
 */

std::vector<std::pair<unsigned short, uint64_t> > GetUDPInboundPorts()
{
    if (!gArgs.IsArgSet("-udpport")) return std::vector<std::pair<unsigned short, uint64_t> >();

    std::map<size_t, std::pair<unsigned short, uint64_t> > res;
    for (const std::string& s : gArgs.GetArgs("-udpport")) {
        size_t port_end = s.find(',');
        size_t group_end = s.find(',', port_end + 1);
        size_t bw_end = s.find(',', group_end + 1);

        if (port_end == std::string::npos || (group_end != std::string::npos && bw_end != std::string::npos)) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t port = atoi64(s.substr(0, port_end));
        if (port != (unsigned short)port || port == 0) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t group = atoi64(s.substr(port_end + 1, group_end - port_end - 1));
        if (group < 0 || res.count(group)) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t bw = 1024;
        if (group_end != std::string::npos) {
            bw = atoi64(s.substr(group_end + 1));
            if (bw < 0) {
                LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
                return std::vector<std::pair<unsigned short, uint64_t> >();
            }
        }

        res[group] = std::make_pair((unsigned short)port, uint64_t(bw));
    }

    std::vector<std::pair<unsigned short, uint64_t> > v;
    for (size_t i = 0; i < res.size(); i++) {
        if (!res.count(i)) {
            LogPrintf("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }
        v.push_back(res[i]);
    }

    return v;
}

void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list) {
    connections_list.clear();
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    connections_list.reserve(mapUDPNodes.size());
    for (const auto& node : mapUDPNodes) {
        connections_list.push_back({node.first, node.second.connection.group, node.second.connection.fTrusted, (node.second.state & STATE_GOT_SYN_ACK) ? node.second.lastRecvTime : 0, {}});
        for (size_t i = 0; i < sizeof(node.second.last_pings) / sizeof(double); i++)
            if (node.second.last_pings[i] != -1)
                connections_list.back().last_pings.push_back(node.second.last_pings[i]);
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    std::pair<std::map<CService, UDPConnectionState>::iterator, bool> res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    if (!res.second) {
        send_and_disconnect(res.first);
        res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    }

    if (info.connection_type != UDP_CONNECTION_TYPE_INBOUND_ONLY)
        maybe_have_write_nodes = true;

    LogPrint(BCLog::UDPNET, "UDP: Initializing connection to %s...\n", addr.ToString());

    UDPConnectionState& state = res.first->second;
    state.connection = info;
    state.state = (info.udp_mode == udp_mode_t::multicast) ? STATE_INIT_COMPLETE : STATE_INIT;
    state.lastSendTime = 0;
    state.lastRecvTime = GetTimeMillis();

    if (info.udp_mode == udp_mode_t::unicast) {
        size_t group_count = 0;
        for (const auto& it : mapUDPNodes)
            if (it.second.connection.group == info.group)
                group_count++;
        min_per_node_mbps = std::min(min_per_node_mbps.load(), mapTxQueues[info.group].bw / group_count);
    }

    if (info.udp_mode == udp_mode_t::multicast) {
        for (size_t i = 0; i < sizeof(state.last_pings) / sizeof(double); i++) {
            state.last_pings[i] = 0;
        }
    }
}

void OpenUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, uint64_t group) {
    OpenUDPConnectionTo(addr, {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type, udp_mode_t::unicast});
}

void OpenPersistentUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, uint64_t group, udp_mode_t udp_mode) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    if (mapPersistentNodes.count(addr))
        return;
    /* NOTE: when multiple multicast services are defined on the same IP:port,
     * only one persistent node is created */

    UDPConnectionInfo info = {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type, udp_mode};
    OpenUDPConnectionTo(addr, info);
    mapPersistentNodes[addr] = info;
}

void CloseUDPConnectionTo(const CService& addr) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    auto it = mapPersistentNodes.find(addr);
    if (it != mapPersistentNodes.end())
        mapPersistentNodes.erase(it);

    auto it2 = mapUDPNodes.find(addr);
    if (it2 == mapUDPNodes.end())
        return;
    DisconnectNode(it2);
}


const std::map<std::tuple<CService, int, uint16_t>, UDPMulticastInfo>& multicast_nodes()
{
    return mapMulticastNodes;
}

bool IsMulticastRxNode(const CService& node) {
    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
    const auto it = mapUDPNodes.find(node);
    if (it == mapUDPNodes.end()) {
        return false;
    }

    UDPConnectionState& conn_state = it->second;
    const UDPConnectionInfo& conn_info = conn_state.connection;
    return (conn_info.udp_mode == udp_mode_t::multicast) && (conn_info.connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY);
}
