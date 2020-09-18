\
// Copyright (c) 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <rpc/server.h>
#include <rpc/protocol.h>
#include <rpc/util.h>

#include <hash.h>
#include <util/strencodings.h>
#include <udpapi.h>
#include <netbase.h>

#include <univalue.h>

using namespace std;

UniValue getudppeerinfo(const JSONRPCRequest& request)
{
    RPCHelpMan{"getudppeerinfo",
        "\nReturns data about each connected UDP unicast peer as a json array of objects.\n",
        {},
        RPCResult{
            "[\n"
            "  {\n"
            "    \"addr\":\"host:port\",        (string)  The ip address and port of the peer\n"
            "    \"group\": nnn                 (numeric) The group this peer belongs to\n"
            "    \"lastrecv\": ttt,             (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
            "    \"ultimatetrust\": true/false  (boolean) Whether this peer, and all of its peers, are trusted\n"
            "    \"min_recent_rtt\": nnn        (numeric) The minimum RTT among recent pings (in ms)\n"
            "    \"max_recent_rtt\": nnn        (numeric) The maximum RTT among recent pings (in ms)\n"
            "    \"avg_recent_rtt\": nnn        (numeric) The average RTT among recent pings (in ms)\n"
            "  }\n"
            "  ,...\n"
            "]\n"
        },
        RPCExamples{
            HelpExampleCli("getudppeerinfo", "")
            + HelpExampleRpc("getudppeerinfo", "")
        }
    }.Check(request);

    vector<UDPConnectionStats> vstats;
    GetUDPConnectionList(vstats);

    UniValue ret(UniValue::VARR);

    for (const UDPConnectionStats& stats : vstats) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("addr", stats.remote_addr.ToString());
        obj.pushKV("group", stats.group);
        obj.pushKV("lastrecv", stats.lastRecvTime);
        obj.pushKV("ultimatetrust", stats.fUltimatelyTrusted);

        double min = 1000000, max = 0, total = 0;

        for (double rtt : stats.last_pings) {
            min = std::min(rtt, min);
            max = std::max(rtt, max);
            total += rtt;
        }

        obj.pushKV("min_recent_rtt", min);
        obj.pushKV("max_recent_rtt", max);
        obj.pushKV("avg_recent_rtt", stats.last_pings.size() == 0 ? 0 : total / stats.last_pings.size());

        ret.push_back(obj);
    }

    return ret;
}

UniValue addudpnode(const JSONRPCRequest& request)
{
    string strCommand;
    if (request.params.size() >= 5)
        strCommand = request.params[4].get_str();
    if (request.fHelp || request.params.size() > 7 || request.params.size() < 5 ||
        (strCommand != "onetry" && strCommand != "add"))
        throw runtime_error(
            RPCHelpMan{"addudpnode",
                "\nAttempts add a node to the UDP addnode list.\n"
                "Or try a connection to a UDP node once.\n",
                {
                    {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The node IP:port"},
                    {"local_magic", RPCArg::Type::STR, RPCArg::Optional::NO, "Our magic secret value for this connection (should be a secure, random string)"},
                    {"remote_magic", RPCArg::Type::STR, RPCArg::Optional::NO, "The node's magic secret value (should be a secure, random string)"},
                    {"ultimately_trusted", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether to trust this peer, and all of its trusted UDP peers, recursively"},
                    {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "'add' to add a persistent connection or 'onetry' to try a connection to the node once"},
                    {"group", RPCArg::Type::NUM, "0", "'add' to add a persistent connection or 'onetry' to try a connection to the node once"},
                    {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "May be one of 'bidirectional', 'inbound_only' or 'I_certify_remote_is_listening_and_not_a_DoS_target_outbound_only'."},
                },
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"")
                    + HelpExampleRpc("addudpnode", "\"192.168.0.6:8333\" \"PA$$WORD\" \"THEIR_PA$$\" false \"onetry\"")
                }
        }.ToString());

    string strNode = request.params[0].get_str();

    CService addr;
    if (!Lookup(strNode.c_str(), addr, -1, true) || !addr.IsValid())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

    string local_pass = request.params[1].get_str();
    uint64_t local_magic = Hash(&local_pass[0], &local_pass[0] + local_pass.size()).GetUint64(0);
    string remote_pass = request.params[2].get_str();
    uint64_t remote_magic = Hash(&remote_pass[0], &remote_pass[0] + local_pass.size()).GetUint64(0);

    bool fTrust = request.params[3].get_bool();

    size_t group = 0;
    if (request.params.size() >= 6)
        group = request.params[5].get_int64();
    if (group > GetUDPInboundPorts().size())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Group out of range or UDP port not bound");

    UDPConnectionType connection_type = UDP_CONNECTION_TYPE_NORMAL;
    if (request.params.size() >= 7) {
        if (request.params[6].get_str() == "inbound_only")
            connection_type = UDP_CONNECTION_TYPE_INBOUND_ONLY;
        else if (request.params[6].get_str() == "I_certify_remote_is_listening_and_not_a_DoS_target_oubound_only")
            connection_type = UDP_CONNECTION_TYPE_OUTBOUND_ONLY;
        else if (request.params[6].get_str() != "bidirectional")
            throw JSONRPCError(RPC_INVALID_PARAMS, "Bad argument for connection type");
    }

    if (strCommand == "onetry")
        OpenUDPConnectionTo(addr, local_magic, remote_magic, fTrust, connection_type, group);
    else if (strCommand == "add")
        OpenPersistentUDPConnectionTo(addr, local_magic, remote_magic, fTrust, connection_type, group, udp_mode_t::unicast);

    return NullUniValue;
}

UniValue disconnectudpnode(const JSONRPCRequest& request)
{
    RPCHelpMan{"disconnectudpnode",
        "\nDisconnects a connected UDP node.\n",
        {
            {"node", RPCArg::Type::STR, RPCArg::Optional::NO, "The node IP:port"},
        },
        RPCResults{},
        RPCExamples{
            HelpExampleCli("disconnectudpnode", "\"192.168.0.6:8333\"")
            + HelpExampleRpc("disconnectudpnode", "\"192.168.0.6:8333\"")
        }
    }.Check(request);

    string strNode = request.params[0].get_str();

    CService addr;
    if (!Lookup(strNode.c_str(), addr, -1, true) || !addr.IsValid())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

    CloseUDPConnectionTo(addr);

    return NullUniValue;
}

UniValue getudpmulticastinfo(const JSONRPCRequest& request) {
    RPCHelpMan{"getudpmulticastinfo",
        "\nRetrieve information about the UDP multicast Rx instances.\n",
        {
        },
        RPCResults{
             RPCResult{
                 "{\n"
                 "  \"peer address\" : {   (json object)\n"
                 "    \"bitrate\"    : (string) Incoming bit rate\n"
                 "    \"group\"      : (numeric) UDP group number\n"
                 "    \"groupname\"  : (string) Group label set on option udpmulticast\n"
                 "    \"ifname\"     : (string) Network interface name\n"
                 "    \"mcast_ip\"   : (string) Multicast IP address this group listens to\n"
                 "    \"port\"       : (numeric) UDP port this group listens to\n"
                 "    \"rcvd_bytes\" : (numeric) Number of bytes received so far\n"
                 "    \"trusted\"    : (boolean) Whether the sending peer is trusted\n"
                 "  }\n"
                 "  ... (all UDP peers)\n"
                 "}\n"
             }
        },
        RPCExamples{
            HelpExampleCli("getudpmulticastinfo", "")
            + HelpExampleRpc("getudpmulticastinfo", "")
        }
    }.Check(request);

    return UdpMulticastRxInfoToJson();
}

static std::string StatsDescriptionString()
{
    return "  \"height\": n,                  (numeric) Block height (if already decoded)\n"
        "  \"header_chunks\": \"rx / exp\",  (string)  Header FEC chunks received / expected\n"
        "  \"body_chunks\": \"rx / exp\",    (string)  Body FEC chunks received / expected\n"
        "  \"progress\": \"x%\"              (string)  Percentage of chunks received\n";
}

UniValue getchunkstats(const JSONRPCRequest& request)
{
    RPCHelpMan{"getchunkstats",
    "\nReturns chunk statistics of current partial blocks.\n",
    {
        {"height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Height of the partial block of interest. If set to 0, shows all current partial blocks."},
    },
    {
        RPCResult{
        "if height is omitted",
        "{\n"
        "\"min_blk\": {                    (json object)\n"
        + StatsDescriptionString()
        + "},\n"
        "\"max_blk\": {                    (json object)\n"
        + StatsDescriptionString()
        + "},\n"
        "\"n_blks\": n,                    (numeric) Total number of partial blocks currently under processing\n"
        "\"n_chunks\": n                   (numeric) Total number of chunks within current partial blocks\n"
        "}\n"
        },
        RPCResult{
        "for height > 0",
        "{                               (json object)\n"
        + StatsDescriptionString()
        + "}\n"
        },
        RPCResult{
        "for height = 0",
        "{                               (json object)\n"
        "  \"block_hash_prefix\": {        (json object)\n"
        + StatsDescriptionString()
        + "  },\n"
        "  ...\n"
        "}\n"
        }
    },
    RPCExamples{
        HelpExampleCli("getchunkstats", "")
        + HelpExampleRpc("getchunkstats", "100000")
    }
    }.Check(request);

    if (request.params[0].isNull())
        return MaxMinBlkChunkStatsToJSON();
    else {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        const int target_height = request.params[0].get_int();
        if (target_height == 0) {
            return AllBlkChunkStatsToJSON();
        } else {
            UniValue info = BlkChunkStatsToJSON(request.params[0].get_int());
            if (info.isNull())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block height not in partial blocks");
            else
                return info;
        }
    }
}

UniValue gettxwindowinfo(const JSONRPCRequest& request) {
    RPCHelpMan{"gettxwindowinfo",
        "\nGet info from the multicast Tx block-interleave window.\n",
        {
            {"physical_idx", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Physical stream index"},
            {"logical_idx", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Logical stream index"},
        },
        RPCResults{
             RPCResult{
                 "When the physical and logical indexes are omitted:\n"
                 "{\n"
                 "  physical_idx-logical_idx : {       (json object)\n"
                 "    \"size\"    : n  (numeric) Total amount (in MB) of FEC data stored in the window\n"
                 "    \"min\"     : n  (numeric) Minimum height currently in the window\n"
                 "    \"max\"     : n  (numeric) Maximum height currently in the window\n"
                 "    \"largest\" : n  (numeric) Height of the largest block currently in the window\n"
                 "  }\n"
                 "  ...\n"
                 "}\n"
             },
             RPCResult{
                 "When the physical and logical indexes are specified:\n"
                 "{\n"
                 "  height : {       (json object) Height of a block in the window\n"
                 "    \"index\" : n  (numeric) Index of next chunk to be transmitted from this block\n"
                 "    \"total\" : n  (numeric) Total number of chunks from this block\n"
                 "  }\n"
                 "  ...\n"
                 "}\n"
             }
        },
        RPCExamples{
            HelpExampleCli("gettxwindowinfo", "")
            + HelpExampleRpc("gettxwindowinfo", "0, 0")
        }
    }.Check(request);

    if (request.params[1].isNull() && !request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMS,
                           "Both physical and logical indexes are required");

    const int phy_idx = request.params[0].isNull() ? -1 :
        request.params[0].get_int();
    const int log_idx = request.params[1].isNull() ? -1 :
        request.params[1].get_int();

    UniValue info = TxWindowInfoToJSON(phy_idx, log_idx);
    if (info.isNull())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Tx stream does not exist");

    return info;
}

UniValue gettxntxinfo(const JSONRPCRequest& request) {
    RPCHelpMan{"gettxntxinfo",
        "\nGet information regarding multicast transmissions of mempool txns.\n",
        {
        },
        RPCResults{
             RPCResult{
                 "{\n"
                 "  physical_idx-logical_idx : {       (json object)\n"
                 "    \"tx_count\" : n  (numeric) Total number of txns transmitted\n"
                 "  }\n"
                 "  ...\n"
                 "}\n"
             }
        },
        RPCExamples{
            HelpExampleCli("gettxntxinfo", "")
            + HelpExampleRpc("gettxntxinfo", "")
        }
    }.Check(request);

    UniValue info = TxnTxInfoToJSON();
    if (info.isNull())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Could not find any txn transmission stream");

    return info;
}

UniValue gettxqueueinfo(const JSONRPCRequest& request) {
    RPCHelpMan{"gettxqueueinfo",
        "\nGet information from the UDP Tx queues.\n",
        {
        },
        RPCResults{
             RPCResult{
                 "{\n"
                 "  \"Group 0\" : {          (json object)\n"
                 "    \"Buffer 0\" : {       (json object)\n"
                 "      \"tx_bytes\"    : n  (numeric) Bytes transmitted through the ring buffer\n"
                 "      \"tx_pkts\"     : n  (numeric) Packets transmitted through the ring buffer\n"
                 "      \"pkt_per_sec\" : n  (numeric) Packets transmitted per second on average\n"
                 "      \"bitrate\"     : n  (numeric) Average bitrate (in bps) of the ring buffer\n"
                 "    }\n"
                 "    \"Buffer 1\" : {       (json object)\n"
                 "        ...\n"
                 "    }\n"
                 "    ... (all buffers)\n"
                 "  }\n"
                 "  ... (all queue groups)\n"
                 "}\n"
             }
        },
        RPCExamples{
            HelpExampleCli("gettxqueueinfo", "")
            + HelpExampleRpc("gettxqueueinfo", "")
        }
    }.Check(request);

    UniValue info = TxQueueInfoToJSON();
    if (info.isNull())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Could not find any Tx queue");

    return info;
}

UniValue getfechitratio(const JSONRPCRequest& request) {
    RPCHelpMan{"getfechitratio",
        "\nGet the last FEC hit ratios achieved on reception of blocks coming via UDP.\n"
        "\nNew blocks are relayed over UDP connections using compact block format. On\n"
        "reception of such a cmpctblock, the node tries to form the original block and\n"
        "tries to prefill the block's txns based on the mempool transactions that it\n"
        "already has. Furthermore, the receiving node tries to prefill the FEC chunks\n"
        "corresponding to the FEC-coded version of the original block, which is sent\n"
        "after the cmpctblock. The hit ratios indicate the number of txns or FEC chunks\n"
        "already available locally in relation to the total number of txns or FEC chunks\n"
        "composing the block.\n",
        {
        },
        RPCResults{
             RPCResult{
                 "{\n"
                 "  \"peer address\" : {   (json object)\n"
                 "    \"txn_ratio\"   : n  (numeric) Txns already available / total txns\n"
                 "    \"chunk_ratio\" : n  (numeric) FEC chunks prefilled / total chunks\n"
                 "  }\n"
                 "  ... (all UDP peers)\n"
                 "}\n"
             }
        },
        RPCExamples{
            HelpExampleCli("getfechitratio", "")
            + HelpExampleRpc("getfechitratio", "")
        }
    }.Check(request);

    return FecHitRatioToJson();
}

UniValue txblock(const JSONRPCRequest& request)
{
    RPCHelpMan{"txblock",
    "Transmit a chosen block over all active UDP multicast Tx streams.\n"
    "\nSends a different set of FEC chunks over each Tx stream.\n",
    {
        {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height."},
    },
    RPCResults{},
    RPCExamples{
        HelpExampleCli("txblock", "600000")
        + HelpExampleRpc("txblock", "600000")
    }
    }.Check(request);

    MulticastTxBlock(request.params[0].get_int());

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "udpnetwork",         "getudppeerinfo",         &getudppeerinfo,         {} },
    { "udpnetwork",         "addudpnode",             &addudpnode,             {"node", "local_magic", "remote_magic", "ultimately_trusted", "command", "group"} },
    { "udpnetwork",         "disconnectudpnode",      &disconnectudpnode,      {"node"} },
    { "udpnetwork",         "getudpmulticastinfo",    &getudpmulticastinfo,    {} },
    { "udpnetwork",         "getchunkstats",          &getchunkstats,          {"height"} },
    { "udpnetwork",         "gettxwindowinfo",        &gettxwindowinfo,        {"physical_idx", "logical_idx"} },
    { "udpnetwork",         "gettxntxinfo",           &gettxntxinfo,           {} },
    { "udpnetwork",         "gettxqueueinfo",         &gettxqueueinfo,         {} },
    { "udpnetwork",         "getfechitratio",         &getfechitratio,         {} },
    { "udpnetwork",         "txblock",                &txblock,                {"height"} }
};

void RegisterUDPNetRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
