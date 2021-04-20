// Copyright (c) 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

// This is the external API to Bitcoin Satellite for use in RPC/validation/etc

#ifndef BITCOIN_UDPAPI_H
#define BITCOIN_UDPAPI_H

#include <net.h>
#include <netaddress.h>
#include <univalue.h>

class CBlock;

std::vector<std::pair<unsigned short, uint64_t> > GetUDPInboundPorts(); // port, outbound bandwidth for group
bool InitializeUDPConnections(CConnman* const connman);
void StopUDPConnections();

enum UDPConnectionType {
    UDP_CONNECTION_TYPE_NORMAL,
    UDP_CONNECTION_TYPE_OUTBOUND_ONLY,
    UDP_CONNECTION_TYPE_INBOUND_ONLY,
};

enum class udp_mode_t : std::uint8_t { multicast, unicast };

// fUltimatelyTrusted means you trust them (ie whitelist) and ALL OF THEIR SUBSEQUENT WHITELISTED PEERS
void OpenUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type = UDP_CONNECTION_TYPE_NORMAL, uint64_t group = 0);
void OpenPersistentUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type = UDP_CONNECTION_TYPE_NORMAL, uint64_t group = 0, udp_mode_t udp_mode = udp_mode_t::unicast);

void CloseUDPConnectionTo(const CService& remote_addr);

struct UDPConnectionStats {
    CService remote_addr;
    uint64_t group;
    bool fUltimatelyTrusted;
    int64_t lastRecvTime;
    std::vector<double> last_pings;
};
void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list);

void UDPRelayBlock(const CBlock& block, int nHeight = -1);

UniValue BlkChunkStatsToJSON(int target_height);
UniValue MaxMinBlkChunkStatsToJSON();
UniValue AllBlkChunkStatsToJSON();
UniValue FecHitRatioToJson();

UniValue UdpMulticastRxInfoToJson();
UniValue TxWindowInfoToJSON(int phy_idx, int log_idx);
UniValue TxnTxInfoToJSON();
UniValue TxQueueInfoToJSON();
void MulticastTxBlock(const int height);

#endif
