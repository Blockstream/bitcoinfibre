// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <udprelay.h>

#include <chainparams.h>
#include <consensus/consensus.h> // for MAX_BLOCK_SERIALIZED_SIZE
#include <consensus/validation.h> // for CValidationState
#include <logging.h>
#include <streams.h>
#include <validation.h>
#include <version.h>
#include <net.h>
#include <net_processing.h>

#include <queue>
#include <condition_variable>
#include <thread>
#include <boost/optional.hpp>

#if BOOST_VERSION < 105600
#include <boost/utility/in_place_factory.hpp> // for boost::in_place
#endif

#include <boost/thread.hpp>

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())
#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

static CService TRUSTED_PEER_DUMMY;
static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > mapPartialBlocks;
static std::unordered_set<uint64_t> setBlocksRelayed;
// In cases where we receive a block without its previous block, or a block
// which is already (to us) an orphan, we will not get a UDPRelayBlock
// callback. However, we do not want to re-process the still-happening stream
// of packets into more ProcessNewBlock calls, so we have to keep a separate
// set here.
static std::set<std::pair<uint64_t, CService>> setBlocksReceived;

static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator RemovePartialBlock(std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it) {
    uint64_t const hash_prefix = it->first.first;
    std::lock_guard<std::mutex> lock(it->second->state_mutex);
    // Note that we do not modify perNodeChunkCount, as it might be "read-only" due to currentlyProcessing
    for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& node : it->second->perNodeChunkCount) {
        std::map<CService, UDPConnectionState>::iterator nodeIt = mapUDPNodes.find(node.first);
        if (nodeIt == mapUDPNodes.end())
            continue;

        // Copy hit ratios saved within the PartialBlockData into the node's
        // UDPConnectionState, which later becomes available for read through
        // the getfechitratio RPC
        if (it->second->txn_hit_ratio != -1 && it->second->chunk_hit_ratio) {
            nodeIt->second.last_txn_hit_ratio = it->second->txn_hit_ratio;
            nodeIt->second.last_chunk_hit_ratio = it->second->chunk_hit_ratio;
        }

        std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = nodeIt->second.chunks_avail.find(hash_prefix);
        if (chunks_avail_it == nodeIt->second.chunks_avail.end())
            continue; // Peer reconnected at some point
        nodeIt->second.chunks_avail.erase(chunks_avail_it);
    }
    /* Now that we are done with the FEC data, remove any underlying mmap FEC chunk files */
    it->second->header_decoder.RemoveMmapFile();
    it->second->body_decoder.RemoveMmapFile();
    return mapPartialBlocks.erase(it);
}

static void RemovePartialBlock(const std::pair<uint64_t, CService>& key) {
    auto it = mapPartialBlocks.find(key);
    if (it != mapPartialBlocks.end())
        RemovePartialBlock(it);
}

static void RemovePartialBlocks(uint64_t const hash_prefix) {
    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it = mapPartialBlocks.lower_bound(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
    while (it != mapPartialBlocks.end() && it->first.first == hash_prefix)
        it = RemovePartialBlock(it);
}

static inline void SendMessageToNode(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix, std::map<CService, UDPConnectionState>::iterator it) {
    if ((it->second.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
        return;

    const bool is_blk_content_chunk = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS;
    const size_t n_chunks = DIV_CEIL(le32toh(msg.msg.block.obj_length), sizeof(UDPBlockMessage::data));
    const uint32_t chunk_id = le32toh(msg.msg.block.chunk_id);

    const auto chunks_avail_it = it->second.chunks_avail.find(hash_prefix);
    bool use_chunks_avail = chunks_avail_it != it->second.chunks_avail.end();

    if (use_chunks_avail) {
        if (chunks_avail_it->second.AreAllAvailable())
            return;

        if (chunks_avail_it->second.IsChunkAvailable(chunk_id, n_chunks, is_blk_content_chunk))
            return;
    }

    SendMessage(msg, length, high_prio, *it);

    if (use_chunks_avail)
        chunks_avail_it->second.SetChunkAvailable(chunk_id, n_chunks, is_blk_content_chunk);
}

static void SendMessageToAllNodes(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix) {
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        if (it->second.connection.connection_type != UDP_CONNECTION_TYPE_INBOUND_ONLY)
            SendMessageToNode(msg, length, high_prio, hash_prefix, it);
}

static size_t CopyMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, size_t msg_chunks, uint16_t chunk_id) {
    msg.msg.block.chunk_id = htole16(chunk_id);

    size_t msg_size = (chunk_id == msg_chunks - 1) ? (data.size() % FEC_CHUNK_SIZE) : sizeof(msg.msg.block.data);
    if (msg_size == 0) msg_size = FEC_CHUNK_SIZE;
    memcpy(msg.msg.block.data, &data[chunk_id * FEC_CHUNK_SIZE], msg_size);
    if (msg_size != sizeof(msg.msg.block.data))
        memset(&msg.msg.block.data[msg_size], 0, sizeof(msg.msg.block.data) - msg_size);
    return msg_size;
}

/**
 * Send uncoded (non FEC-coded) data chunks to all peers
 */
static void RelayUncodedChunks(UDPMessage& msg, const std::vector<unsigned char>& data, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix, const size_t chunk_limit) {
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

    bool high_prio = high_prio_chunks_per_peer;

    for (uint16_t i = 0; i < msg_chunks && i < chunk_limit; i++) {
        if (high_prio && i >= high_prio_chunks_per_peer)
            high_prio = false;

        /* Send the same uncoded chunk to all peers */
        CopyMessageData(msg, data, msg_chunks, i);

        for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
            if (it->second.connection.udp_mode == udp_mode_t::unicast)
                SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), high_prio, hash_prefix, it);
        }

        for (const auto& node : multicast_nodes()) {
            if (node.second.tx && node.second.relay_new_blks) {
                SendMessage(msg,
                            sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage),
                            high_prio, std::get<0>(node.first),
                            multicast_checksum_magic, node.second.group);
            }
        }
    }
}

struct DataFECer {
    size_t fec_chunks;
    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> fec_data;
    FECEncoder enc;
    DataFECer(const std::vector<unsigned char>& data, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
        enc(&data, &fec_data) {}

    DataFECer(FECDecoder&& decoder, const std::vector<unsigned char>& data, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
        enc(std::move(decoder), &data, &fec_data) {}

#if BOOST_VERSION < 105600
    // This is only necessary in order to construct this via a boost::in_place,
    // which is pre-c++11 and can only take arguments by value
    DataFECer(FECDecoder* decoder, const std::vector<unsigned char>& data, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
        enc(std::move(*decoder), &data, &fec_data) {}
#endif
};

static void CopyFECData(UDPMessage& msg, DataFECer& fec, size_t array_idx, bool overwrite_chunk = false) {
    bool const ret = fec.enc.BuildChunk(array_idx, overwrite_chunk);
    // TODO: Handle errors?
    assert(ret);
    assert(fec.fec_data.second[array_idx] < (1 << 24));
    msg.msg.block.chunk_id = htole32(fec.fec_data.second[array_idx]);
    memcpy(msg.msg.block.data, &fec.fec_data.first[array_idx], FEC_CHUNK_SIZE);
}

/**
 * Send FEC-coded chunks to all peers
 *
 * For each chunk index, a different (random) chunk id is generated for each
 * outbound service. This is useful for receive peers that are receiving from
 * (combining) more than one service.
 */
static void RelayFECedChunks(UDPMessage& msg, DataFECer& fec, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix) {
    assert(fec.fec_chunks > 9);

    bool high_prio = high_prio_chunks_per_peer;
    for (size_t i = 0; i < fec.fec_chunks; i++) {
        if (high_prio && (i >= high_prio_chunks_per_peer))
            high_prio = false;

        /* Send over unicast services */
        for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
            if (it->second.connection.udp_mode == udp_mode_t::unicast) {
                CopyFECData(msg, fec, i, true /*regenerate chunk on index i*/);
                SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), high_prio, hash_prefix, it);
            }
        }

        /* Send over each multicast Tx (outbound) service */
        for (const auto& node : multicast_nodes()) {
            if (node.second.tx && node.second.relay_new_blks) {
                CopyFECData(msg, fec, i, true /*regenerate chunk on index i*/);
                SendMessage(msg,
                            sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage),
                            high_prio, std::get<0>(node.first),
                            multicast_checksum_magic, node.second.group);
            }
        }
    }
}

static inline void FillCommonMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, uint8_t type, const size_t obj_size) {
    msg.header.chk1            = 0;
    msg.header.chk2            = 0;
    msg.header.msg_type        = type;
    msg.msg.block.hash_prefix  = htole64(hash_prefix);
    msg.msg.block.obj_length   = htole32(obj_size);
}

static inline void FillBlockMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, UDPMessageType type, const size_t obj_size, uint8_t flags = HAVE_BLOCK) {
    // First fill in common message elements
    FillCommonMessageHeader(msg, hash_prefix, type | flags, obj_size);
}

/**
 * Send FEC-coded and uncoded (original data) chunks to all peers
 *
 * This function processes either header chunks or block chunks, but not
 * both. So it has to be called twice. After completion, all chunks (of the
 * header or block) will be queued up for transmission.
 */
static void RelayChunks(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data, DataFECer& fec) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    FillBlockMessageHeader(msg, hash_prefix, type, data.size(), (HAVE_BLOCK | TIP_BLOCK));

    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    std::chrono::steady_clock::time_point t_start, t_uncoded, t_coded;
    if (fBench)
        t_start = std::chrono::steady_clock::now();

    // For header messages, the actual data is more useful.
    // For block contents, the probably generated most chunks from the header + mempool.
    // We send in usefulness-first order
    if (type == MSG_TYPE_BLOCK_HEADER) {
        // Block headers are all high priority for the data itself,
        // and 3 packets of high priority for the FEC, after that if
        // we have block data available it should be sent.
        RelayUncodedChunks(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, std::numeric_limits<size_t>::max());
        if (fBench)
            t_uncoded = std::chrono::steady_clock::now();

        RelayFECedChunks(msg, fec, 3, hash_prefix);
        if (fBench)
            t_coded = std::chrono::steady_clock::now();
    } else {
        // First 100 FEC chunks are high priority, then everything is low. This
        // should be sufficient to reconstruct many blocks that only missed a
        // handful of chunks, then revert to sending header chunks until we've
        // sent them all.
        RelayFECedChunks(msg, fec, 100, hash_prefix);
        /* NOTE: there is no need to send uncoded block data. Sending uncoded
         * makes sense when the receive-end doesn't know anything about the
         * data. However, here the receiver is assumed to known most of the
         * data, so sending FEC-coded chunks is preferable. */
        if (fBench)
            t_coded = std::chrono::steady_clock::now();
    }

    if (fBench) {
        const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

        if (type == MSG_TYPE_BLOCK_HEADER) {
            LogPrintf("UDP: %s: Finished queuing of %lu header chunks for tx - took %lf ms\n",
                      __func__, (msg_chunks + fec.fec_chunks),
                      to_millis_double(t_coded - t_start));
            LogPrintf("UDP: %s:     %lu Uncoded header chunks took %lf ms\n", __func__,
                      msg_chunks, to_millis_double(t_uncoded - t_start));
            LogPrintf("UDP: %s:     %lu Coded header chunks took %lf ms\n", __func__,
                      fec.fec_chunks, to_millis_double(t_coded - t_uncoded));
        } else {
            LogPrintf("UDP: %s: Finished queuing of %lu FEC-coded block chunks for tx - took %lf ms\n",
                      __func__, (fec.fec_chunks),
                      to_millis_double(t_coded - t_start));
        }
    }
}

static void SendLimitedDataChunks(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    FillBlockMessageHeader(msg, hash_prefix, type, data.size(), (HAVE_BLOCK | TIP_BLOCK));

    RelayUncodedChunks(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, 3); // Send 3 packets to each peer, in RR
}

static std::unique_ptr<std::thread> process_block_thread;

void UDPRelayBlock(const CBlock& block, int nHeight) {
    std::chrono::steady_clock::time_point start;
    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    if (fBench)
        start = std::chrono::steady_clock::now();

    uint256 hashBlock(block.GetHash());
    uint64_t hash_prefix = hashBlock.GetUint64(0);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes, std::defer_lock);

    if (maybe_have_write_nodes) { // Scope for partial_block_lock and partial_block_ptr
        const std::vector<unsigned char> *chunk_coded_block = NULL;
        bool skipEncode = false;
        std::unique_lock<std::mutex> partial_block_lock;
        std::shared_ptr<PartialBlockData> partial_block_ptr;
        bool inUDPProcess = process_block_thread && std::this_thread::get_id() == process_block_thread->get_id();
        if (inUDPProcess) {
            lock.lock();

            auto it = mapPartialBlocks.find(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
            if (it != mapPartialBlocks.end() && it->second->currentlyProcessing) {
                partial_block_lock = std::unique_lock<std::mutex>(it->second->state_mutex); // Locked after cs_mapUDPNodes
                if (it->second->block_data.AreChunksAvailable()) {
                    if (fBench)
                        LogPrintf("UDP: Building FEC chunks from decoded block\n");
                    skipEncode = true;
                    partial_block_ptr = it->second;
                    chunk_coded_block = &it->second->block_data.GetCodedBlock();
                }
            }

            // We unlock everything here to let the net thread relay packets,
            // but continue to use data which is theoretically under the locks.
            // This is OK - we get a copy of the shared_ptr and hold it in
            // partial_block_ptr so it wont be destroyed out from under us, and
            // are only using the chunks from PartiallyDownloadedChunkBlock and
            // the decoder, both of which, once available, will never become
            // un-available or be modified by any other thread (due to the
            // currentlyProcessing checks made in the net thread).
            // We should not otherwise be making assumptions about availability of
            // block-related data, but eg the message send functions check for the
            // availability of ChunkAvailableSets prior to access.
            if (partial_block_lock)
                partial_block_lock.unlock();
            lock.unlock();
        }

        std::chrono::steady_clock::time_point initd;
        if (fBench)
            initd = std::chrono::steady_clock::now();

        boost::optional<ChunkCodedBlock> codedBlock;
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, codec_version_t::default_version, true);
        headerAndIDs.setBlockHeight(nHeight);
        std::vector<unsigned char> header_data;
        header_data.reserve(2500 + 8 * block.vtx.size()); // Rather conservatively high estimate
        VectorOutputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
        stream << headerAndIDs;

        std::chrono::steady_clock::time_point coded;
        if (fBench)
            coded = std::chrono::steady_clock::now();

        const size_t header_fec_chunks = DIV_CEIL(header_data.size(), FEC_CHUNK_SIZE) + 10;
        DataFECer header_fecer(header_data, header_fec_chunks);

        boost::optional<DataFECer> block_fecer;
        size_t data_fec_chunks = 0;
        if (inUDPProcess) {
            // If we're actively receiving UDP packets, go ahead and spend the time to precalculate FEC now,
            // otherwise we want to start getting the header/first block chunks out ASAP
            header_fecer.enc.PrefillChunks();

            if (!skipEncode) {
#if BOOST_VERSION >= 105600
                codedBlock.emplace(block, headerAndIDs);
#else
                codedBlock = boost::in_place(block, headerAndIDs);
#endif
                chunk_coded_block = &codedBlock->GetCodedBlock();
            }
            if (!chunk_coded_block->empty()) {
                data_fec_chunks = DIV_CEIL(chunk_coded_block->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                if (skipEncode) {
                    // If we get here, we are currently in the processing thread
                    // and have partial_block_ptr set. Additionally, because
                    // partial_block_ptr->block_data has chunks, the FEC decoder
                    // was initialized and fed FEC/data, meaning even if no FEC
                    // chunks were used to reconstruct the FECDecoder object is
                    // fully primed to be converted to a FECEncoder!
#if BOOST_VERSION >= 105600
                    block_fecer.emplace(std::move(partial_block_ptr->body_decoder), *chunk_coded_block, data_fec_chunks);
#else
                    // this moves body_decoder into the block_fecer
                    block_fecer = boost::in_place(&partial_block_ptr->body_decoder, *chunk_coded_block, data_fec_chunks);
#endif
                } else {
#if BOOST_VERSION >= 105600
                    block_fecer.emplace(*chunk_coded_block, data_fec_chunks);
#else
                    block_fecer = boost::in_place(*chunk_coded_block, data_fec_chunks);
#endif
                }
                block_fecer->enc.PrefillChunks();
            }
        }

        std::chrono::steady_clock::time_point feced;
        if (fBench)
            feced = std::chrono::steady_clock::now();

        // We do all the expensive calculations before locking cs_mapUDPNodes
        // so that the forward-packets-without-block logic in HandleBlockMessage
        // continues without interruption as long as possible
        if (!lock)
            lock.lock();

        if (mapUDPNodes.empty())
            return;

        if (setBlocksRelayed.count(hash_prefix))
            return;

        RelayChunks(hashBlock, MSG_TYPE_BLOCK_HEADER, header_data, header_fecer);

        std::chrono::steady_clock::time_point header_sent;
        if (fBench)
            header_sent = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!skipEncode) {
#if BOOST_VERSION >= 105600
                codedBlock.emplace(block, headerAndIDs);
#else
                codedBlock = boost::in_place(block, headerAndIDs);
#endif
                chunk_coded_block = &codedBlock->GetCodedBlock();
            }

            // Because we need the coded block's size to init block decoding, it
            // is important we get the first block packet out to peers ASAP. Thus,
            // we go ahead and send the first few non-FEC block packets here.
            if (!chunk_coded_block->empty()) {
                data_fec_chunks = DIV_CEIL(chunk_coded_block->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                SendLimitedDataChunks(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *chunk_coded_block);
            }
        }

        std::chrono::steady_clock::time_point block_coded;
        if (fBench)
            block_coded = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!chunk_coded_block->empty()) {
#if BOOST_VERSION >= 105600
                block_fecer.emplace(*chunk_coded_block, data_fec_chunks);
#else
                block_fecer = boost::in_place(*chunk_coded_block, data_fec_chunks);
#endif
            }
        }

        std::chrono::steady_clock::time_point block_fec_initd;
        if (fBench)
            block_fec_initd = std::chrono::steady_clock::now();

        // Now (maybe) send the transaction chunks
        if (!chunk_coded_block->empty())
            RelayChunks(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *chunk_coded_block, *block_fecer);

        if (fBench) {
            std::chrono::steady_clock::time_point all_sent(std::chrono::steady_clock::now());
            LogPrintf("UDP: Built all FEC chunks for block %s (%lu) in %lf %lf %lf %lf %lf %lf %lf ms with %lu header chunks\n", hashBlock.ToString(), hash_prefix, to_millis_double(initd - start), to_millis_double(coded - initd), to_millis_double(feced - coded), to_millis_double(header_sent - feced), to_millis_double(block_coded - header_sent), to_millis_double(block_fec_initd - block_coded), to_millis_double(all_sent - block_fec_initd), header_fecer.fec_chunks);
            if (!inUDPProcess)
                LogPrintf("UDP: Block %s had serialized size %lu\n", hashBlock.ToString(), GetSerializeSize(block, PROTOCOL_VERSION));
        } else
            LogPrintf("UDP: Built all FEC chunks for block %s\n", hashBlock.ToString());

        // Destroy partial_block_lock before we RemovePartialBlocks()
    }

    setBlocksRelayed.insert(hash_prefix);
    RemovePartialBlocks(hash_prefix);
}

/**
 * Send txn over one or more messages
 *
 * All txns are sent uncoded (without FEC-coding). Yet, the txns with size
 * yielding more than a single data chunk are still treated as FEC-coded on the
 * receive-end. This is OK, , since the coding schemes (cm256 or wirehair) are
 * systematic. Most likely, such (larger) txns will be encoded by cm256.
 *
 * Also, txns are sent over variable-length UDP datagrams. If the txn size is
 * greater than a FEC chunk size, it is split into multiple messages (UDP
 * datagrams), each one (except the last) carrying a number of bytes equal to
 * the FEC chunk size. Otherwise, the txn is sent over a shorter datagram. This
 * function includes the size of each msg into the vector of msgs.
 */
void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<std::pair<UDPMessage, size_t>>& msgs) {
    const uint256 hash(tx.GetWitnessHash());
    const uint64_t hash_prefix = hash.GetUint64(0);

    std::vector<unsigned char> data;
    VectorOutputStream stream(&data, SER_NETWORK, PROTOCOL_VERSION);

    codec_version_t const codec_version = codec_version_t::default_version;
    stream << static_cast<std::uint8_t>(codec_version);
    stream << CTxCompressor(tx, codec_version);

    const size_t data_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    msgs.resize(data_chunks);

    for (size_t i = 0; i < data_chunks; i++) {
        FillCommonMessageHeader(msgs[i].first, hash_prefix, MSG_TYPE_TX_CONTENTS, data.size());
        const size_t chunk_size = CopyMessageData(msgs[i].first, data, data_chunks, i);
        msgs[i].second = sizeof(UDPMessageHeader) + udp_blk_msg_header_size + chunk_size;
    }
}

/**
 * Fill FEC messages of block header and block data
 *
 * This is used by the multicast Tx (backfill) thread only, specifically to send
 * "past blocks", i.e. blocks that are already in the chain. When a new block
 * arises and before it is added to the chain, it is instead relayed to UDP
 * peers through function `UDPRelayBlock`.
 *
 * Unlike txns, only FEC-coded chunks are sent for block data. The same strategy
 * is applied also for transmission of the block header, although based on a
 * different motivation, explained next.
 *
 * The main factor to consider when choosing between sending uncoded vs. coded
 * is whether the receive-end might know something about the data object in
 * advance. Once a block is advertised by the "block header" message, the
 * receive node tries to prefill the chunk-coded block based on the txns that it
 * already has locally in its mempool. As a result, the receive node typically
 * prefills most of the chunks before the chunk-coded block even starts to
 * arrive. In this scenario, it is advantageous to send only coded chunks. The
 * rationale is that each coded chunk generated by the fountain code (wirehair)
 * brings information about multiple other chunks (it is a XOR of multiple
 * chunks) and, as a result, the receive end tends to fill all gaps faster by
 * processing them. In contrast, uncoded chunks only bring their own
 * information, so the receive node must receive the exact chunks that are
 * missing in order to fill all gaps, which tends to be slower.
 *
 * In contrast, for objects that the receiver knows nothing about, it can be
 * slightly advantageous to send the uncoded chunks first. Since the code is
 * systematic, sending uncoded is equivalent to sending coded chunks with chunk
 * id < N, where N is the number of chunks of the original object. The reason
 * why it could be advantageous is that the decoder can process the "uncoded
 * chunks" faster (there is less computation involved). On the other hand, when
 * uncoded chunks are sent, the disadvantage is that the receive-end cannot
 * efficiently combine multiple incoming streams in order to decode the object
 * faster. When, instead, coded chunks with random chunk ids are sent, the
 * receive node that listens to multiple streams will get different chunks from
 * each stream and, consequently, complete the decoding quicker.
 *
 * So the choice for objects that the receiver doesn't know about in advance
 * depends on which factor matters the most: the longer decoding of coded chunks
 * (with random chunk ids) or the more efficient combination of chunks when
 * receiving from multiple streams. It turns out that the decoding is typically
 * in the order of microseconds. Meanwhile, transmission of chunks depends on
 * link bitrates. In the implementation that follows, we optimize for low
 * bitrate links (such as satellite links), where the bottleneck typically is
 * the transmission delay of chunks. For instance, on a 1 Mbps link, a 1 KByte
 * chunk has a delay of 8 ms, i.e. much larger than the decoding latency. Hence,
 * we choose to send all chunks as FEC-coded, even for the block header.
 *
 * Besides, the block header will essentially always be coded via cm256 (rather
 * than wirehair), due to its smaller size (compared to the chunk-coded
 * block). The difference on decoding duration will be even lower in this case.
 *
 * The ensuing function fills all FEC chunks of both header and block data. The
 * order on which chunks are filled is noteworthy. It is optimized for minimum
 * latency in the absence of data loss. First the minimum amount of chunks of
 * header and block data are sent. Receivers that succesfully decode all of
 * these can then complete the decoding right away. After them, the overhead
 * header chunks are sent and, lastly, the overhead block chunks.
 *
 */
void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs,
                              const int height, const size_t base_overhead,
                              const double overhead) {
    const uint256 hashBlock(block.GetHash());
    const uint64_t hash_prefix = hashBlock.GetUint64(0);

    /* Block header */
    CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, codec_version_t::default_version, true);
    headerAndIDs.setBlockHeight(height);
    /* NOTE: it is not mandatory to include the block height along
     * CBlockHeaderAndLengthShortTxIDs. However, it is useful to include it here
     * in order to support out-of-order block (OOOB) storage of pre-BIP34
     * blocks. The reason is that pre-BIP34 blocks don't include the height as
     * part of the coinbase transaction's input script, and so unless we send
     * the height explicitly, the receive node won't know the height and won't
     * be able to store the block in case it is received out-of-order. */

    const bool empty_block = (headerAndIDs.ShortTxIdCount() == 0);
    const uint8_t flags    = empty_block ? (HAVE_BLOCK | EMPTY_BLOCK) : HAVE_BLOCK;

    std::vector<unsigned char> header_data;
    header_data.reserve(2500 + 8 * block.vtx.size()); // Rather conservatively high estimate
    VectorOutputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
    stream << headerAndIDs;
    const size_t n_header_chunks = DIV_CEIL(header_data.size(), FEC_CHUNK_SIZE);
    const size_t header_overhead = base_overhead + std::round(overhead * n_header_chunks);
    const size_t n_header_fec_chunks = n_header_chunks + header_overhead;
    DataFECer header_fecer(header_data, n_header_fec_chunks);
    /* NOTE: the block header will typically be encoded by cm256, due to its
     * size. Since cm256 is MDS, in principle only the N original chunks are
     * necessary. Nevertheless, since chunks can be lost along the transport
     * link, some chunks of overhead are used. */

    /* First fill the minimum amount of header chunks for decoding
     *
     * NOTE: since cm256 is MDS, the minimum amount of header chunks is
     * guaranteed to be sufficient for decoding */
    int offset = msgs.size();
    msgs.resize(offset + n_header_chunks);
    for (size_t i = 0; i < n_header_chunks; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_HEADER, header_data.size(), flags);
        CopyFECData(msgs[offset + i], header_fecer, i);
    }

    /* Don't send the chunk-coded block if the block does not have any
     * transaction other than the coinbase (which is sent in the header) */
    if (empty_block) {
        /* Fill overhead header chunks */
        offset = msgs.size();
        msgs.resize(offset + header_overhead);
        for (size_t i = 0; i < header_overhead; i++) {
            FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_HEADER, header_data.size(), flags);
            CopyFECData(msgs[offset + i], header_fecer, n_header_chunks + i);
        }
        return;
    }

    ChunkCodedBlock codedBlock(block, headerAndIDs);
    const std::vector<unsigned char>& chunk_coded_block = codedBlock.GetCodedBlock();
    const size_t n_block_chunks = DIV_CEIL(chunk_coded_block.size(), FEC_CHUNK_SIZE);
    const size_t block_overhead = base_overhead + std::round(overhead * n_block_chunks);
    const size_t n_block_fec_chunks = n_block_chunks + block_overhead;
    /* NOTE: on average wirehair needs about 0.02 chunks of overhead to recover,
     * meaning most often it doesn't need overhead at all. Again, we add
     * overhead chunks here in order to overcome loss along the link. */
    DataFECer block_fecer(chunk_coded_block, n_block_fec_chunks);

    /* Minimum amount of block chunks for decoding
     *
     * NOTE: unlike header chunks, this minimum amount sent here is only almost
     * always sufficient for decoding, but not 100% guaranteed. */
    offset = msgs.size();
    msgs.resize(offset + n_block_chunks);
    for (size_t i = 0; i < n_block_chunks; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_CONTENTS, chunk_coded_block.size(), flags);
        CopyFECData(msgs[offset + i], block_fecer, i);
    }

    /* Overhead header chunks */
    offset = msgs.size();
    msgs.resize(offset + header_overhead);
    for (size_t i = 0; i < header_overhead; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_HEADER, header_data.size(), flags);
        CopyFECData(msgs[offset + i], header_fecer, n_header_chunks + i);
    }

    /* Overhead block chunks */
    offset = msgs.size();
    msgs.resize(offset + block_overhead);
    for (size_t i = 0; i < block_overhead; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_CONTENTS, chunk_coded_block.size(), flags);
        CopyFECData(msgs[offset + i], block_fecer, n_block_chunks + i);
    }

    return;
}

static std::mutex block_process_mutex;
static std::condition_variable block_process_cv;
static std::atomic_bool block_process_shutdown(false);
static std::queue<std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > > block_process_queue;
static size_t queue_size_warn = 10; // Print queue size when it exceeds this

static void DoBackgroundBlockProcessing(const std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >& block_data) {
    // If we just blindly call ProcessNewBlock here, we have a cs_main/cs_mapUDPNodes inversion
    // (actually because fucking P2P code calls everything with cs_main already locked).
    // Instead we pass the processing back to ProcessNewBlockThread without cs_mapUDPNodes
    std::unique_lock<std::mutex> lock(block_process_mutex);
    block_process_queue.emplace(block_data);
    if (block_process_queue.size() > queue_size_warn) {
        LogPrint(BCLog::FEC, "Block process queue size: %ld\n",
                 block_process_queue.size());
    }
    lock.unlock();
    block_process_cv.notify_all();
}

static void ProcessBlockThread() {
    const bool fBench = LogAcceptCategory(BCLog::BENCH);

    while (true) {
        std::unique_lock<std::mutex> process_lock(block_process_mutex);
        while (block_process_queue.empty() && !block_process_shutdown)
            block_process_cv.wait(process_lock);

        if (block_process_shutdown)
            return;

        auto process_block = block_process_queue.front();
        CService& node = process_block.first.second;
        PartialBlockData& block = *process_block.second;
        block_process_queue.pop();
        process_lock.unlock();

        bool more_work;
        std::unique_lock<std::mutex> lock(block.state_mutex);
        block.awaiting_processing = false;
        do {
            more_work = false;
            if (block.is_header_processing) {
                std::chrono::steady_clock::time_point decode_start;
                if (fBench)
                    decode_start = std::chrono::steady_clock::now();

                std::vector<unsigned char> header_data = block.header_decoder.GetDecodedData();

                std::chrono::steady_clock::time_point data_copied;
                if (fBench)
                    data_copied = std::chrono::steady_clock::now();

                CBlockHeaderAndLengthShortTxIDs header;
                try {
                    VectorInputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
                    stream >> header;
                } catch (std::ios_base::failure& e) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    if (node == TRUSTED_PEER_DUMMY)
                        LogPrintf("UDP: Failed to decode received header and short txids from trusted peer(s), check your trusted peers are behaving well.\n");
                    else {
                        LogPrintf("UDP: Failed to decode received header and short txids from %s, disconnecting\n", node.ToString());
                        const auto it = mapUDPNodes.find(node);
                        if (it != mapUDPNodes.end())
                            DisconnectNode(it);
                    }
                    break;
                }
                std::chrono::steady_clock::time_point header_deserialized;
                if (fBench)
                    header_deserialized = std::chrono::steady_clock::now();

                /* We may not process the header yet (depending on conditions
                 * checked below), but at least we can extract the block height
                 * from the header and save it on the partial block. */
                block.height = header.getBlockHeight();

                /* Do we have the block already?  */
                if (!block.chain_lookup) {
                    const CBlockIndex* pblockindex;
                    {
                        LOCK(cs_main);
                        pblockindex = LookupBlockIndex(header.header.GetHash());
                    }
                    block.chain_lookup = true;
                    if (pblockindex) {
                        /* We do have the block already. Drop the partial block
                         * immediately and add it to setBlocksReceived, so that its
                         * subsequent chunks are ignored.*/
                        lock.unlock();
                        std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                        setBlocksReceived.insert(process_block.first);
                        RemovePartialBlock(process_block.first);
                        break;
                    }
                }

                /* Continue with the processing of a non-tip (repeated) block
                 * only if the body is also decodable or empty. This is to save
                 * memory, given that as soon as we call ProvideHeaderData
                 * below, significant amounts of memory are preallocated. */
                const bool non_empty_block = (header.ShortTxIdCount() != 0);
                if (!block.tip_blk && non_empty_block && !block.is_decodeable)
                    break;

                ReadStatus decode_status = block.ProvideHeaderData(header);
                if (decode_status != READ_STATUS_OK) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    if (decode_status == READ_STATUS_INVALID) {
                        if (node == TRUSTED_PEER_DUMMY)
                            LogPrintf("UDP: Got invalid header and short txids from trusted peer(s), check your trusted peers are behaving well.\n");
                        else {
                            LogPrintf("UDP: Got invalid header and short txids from %s, disconnecting\n", node.ToString());
                            const auto it = mapUDPNodes.find(node);
                            if (it != mapUDPNodes.end())
                                DisconnectNode(it);
                        }
                    } else
                        LogPrintf("UDP: Failed to read header and short txids\n");

                    // Dont remove the block, let it time out...
                    break;
                }

                if (block.block_data.IsBlockAvailable())
                    block.is_decodeable = true;
                block.is_header_processing = false;

                const uint256 blockHash = block.block_data.GetBlockHash();

                if (fBench) {
                    std::chrono::steady_clock::time_point header_provided(std::chrono::steady_clock::now());
                    LogPrintf("UDP: Block %s (height %7d) - Got full header and shorttxids from %s in %lf %lf %lf ms\n", blockHash.ToString(), block.height, block.GetSenders(), to_millis_double(data_copied - decode_start), to_millis_double(header_deserialized - data_copied), to_millis_double(header_provided - header_deserialized));
                } else
                    LogPrintf("UDP: Block %s (height %7d) - Got full header and shorttxids from: [%s]\n", blockHash.ToString(), block.height, block.GetSenders());

                if (block.block_data.AreAllTxnsInMempool())
                    LogPrintf("UDP: Block %s - Ready to be decoded (all txns available)\n", blockHash.ToString());
                else if (block.block_data.IsBlockAvailable())
                    LogPrintf("UDP: Block %s - Ready to be decoded (all uncoded chunks available)\n", blockHash.ToString());
                else if (block.is_decodeable)
                    LogPrintf("UDP: Block %s - Ready to be decoded (enough FEC chunks available)\n", blockHash.ToString());

                if (block.tip_blk) {
                    size_t mempool_txns = block.block_data.GetMempoolCount();
                    size_t n_blk_txns   = header.BlockShortTxCount();
                    block.txn_hit_ratio = (double) mempool_txns / n_blk_txns;
                    LogPrint(BCLog::FEC, "UDP: Block %s - Txns available: %ld/%ld  Txn hit ratio: %f\n",
                             blockHash.ToString(), mempool_txns, n_blk_txns, block.txn_hit_ratio);
                    // When all txns are available in the mempool, the FEC-coded
                    // block is not even decoded. The block is decoded directly
                    // based on the local txns. However, mark as if all chunks
                    // were available for consistency with the txn hit ratio.
                    if (block.block_data.AreAllTxnsInMempool())
                        block.chunk_hit_ratio = 1.0;
                }

                // Do more work if we can already decode the block or in case we
                // should try to fill in the erasures based on mempool txns that
                // we already have (for new blocks, i.e., tip blocks)
                if (block.is_decodeable || (block.blk_initialized && block.tip_blk))
                    more_work = true;
                else
                    lock.unlock();

            } else if (block.block_data.IsHeaderNull()) {
                /* If we are not going to process the header data now, it is
                 * because we are either going to process block data or fill
                 * block data. However, in order for this to succeed we must
                 * have had processed the header before. Double check. */
                break;
            } else if (block.is_decodeable || block.block_data.IsBlockAvailable()) {
                if (block.currentlyProcessing) {
                    // We often duplicatively schedule DoBackgroundBlockProcessing,
                    // but we do not do anything to avoid duplicate
                    // final-processing. Thus, we have to check if we have already
                    // done final processing by checking currentlyProcessing (which
                    // is never un-set after we set it).
                    break;
                }
                block.currentlyProcessing = true;
                std::chrono::steady_clock::time_point reconstruct_start;
                if (fBench)
                    reconstruct_start = std::chrono::steady_clock::now();

                if (!block.block_data.IsBlockAvailable()) {
                    block.ReconstructBlockFromDecoder();
                    assert(block.block_data.IsBlockAvailable());
                }

                std::chrono::steady_clock::time_point fec_reconstruct_finished;
                if (fBench)
                    fec_reconstruct_finished = std::chrono::steady_clock::now();

                ReadStatus status = block.block_data.FinalizeBlock();

                std::chrono::steady_clock::time_point block_finalized;
                if (fBench)
                    block_finalized = std::chrono::steady_clock::now();

                if (status != READ_STATUS_OK) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);

                    if (status == READ_STATUS_INVALID) {
                        if (node == TRUSTED_PEER_DUMMY)
                            LogPrintf("UDP: Unable to decode block from trusted peer(s), check your trusted peers are behaving well.\n");
                        else {
                            const auto it = mapUDPNodes.find(node);
                            if (it != mapUDPNodes.end())
                                DisconnectNode(it);
                        }
                    }
                    setBlocksReceived.insert(process_block.first);
                    RemovePartialBlock(process_block.first);
                    break;
                } else {
                    std::shared_ptr<const CBlock> pdecoded_block = block.block_data.GetBlock();
                    const CBlock& decoded_block = *pdecoded_block;
                    if (fBench) {
                        uint32_t total_chunks_recvd = 0, total_chunks_used = 0;
                        std::map<CService, std::pair<uint32_t, uint32_t> >& chunksProvidedByNode = block.perNodeChunkCount;
                        for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& provider : chunksProvidedByNode) {
                            total_chunks_recvd += provider.second.second;
                            total_chunks_used += provider.second.first;
                        }
                        /* NOTE: the chunk count printed next is not necessarily
                         * accurate. It reflects the count up to when the block
                         * is decoded. However, further chunks may still be
                         * received after the block is decoded. */
                        LogPrintf("UDP: Block %s reconstructed with %u chunks in %lf ms (%u recvd from %u peers)\n", decoded_block.GetHash().ToString(), total_chunks_used, to_millis_double(std::chrono::steady_clock::now() - block.timeHeaderRecvd), total_chunks_recvd, chunksProvidedByNode.size());
                        for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& provider : chunksProvidedByNode)
                            LogPrintf("UDP:    %u/%u used from %s\n", provider.second.first, provider.second.second, provider.first.ToString());
                    }

                    lock.unlock();

                    std::chrono::steady_clock::time_point process_start;
                    if (fBench)
                        process_start = std::chrono::steady_clock::now();

                    /* Treat the block as a solicited block in case it came from
                     * a trusted peer */
                    const bool force_requested = (node == TRUSTED_PEER_DUMMY);

                    bool fNewBlock;
                    if (!ProcessNewBlock(Params(), pdecoded_block, force_requested, &fNewBlock)) {
                        bool have_prev, outoforder_and_valid;
                        {
                            LOCK(cs_main);

                            have_prev = BlockIndex().count(pdecoded_block->hashPrevBlock);
                            CValidationState state;
                            outoforder_and_valid = !have_prev &&
                                CheckBlock(*pdecoded_block, state, Params().GetConsensus());
                        }

                        LogPrintf("UDP: Failed to decode block %s\n", decoded_block.GetHash().ToString());

                        /* Only save out-of-order blocks that are minimally
                         * valid */
                        bool ooob_saved = false;
                        if (outoforder_and_valid)
                            ooob_saved = StoreOoOBlock(Params(), pdecoded_block, force_requested, block.height);

                        std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);

                        if (have_prev || ooob_saved) {
                            setBlocksReceived.insert(process_block.first);
                        } else {
                            // Allow re-downloading again later, useful for local backfill downloads
                            setBlocksReceived.erase(process_block.first);
                        }
                        RemovePartialBlock(process_block.first);
                        break; // Probably a tx collision generating merkle-tree errors
                    }
                    if (fBench) {
                        LogPrintf("UDP: Final block processing for %s took %lf %lf %lf %lf ms (new: %d)\n", decoded_block.GetHash().ToString(), to_millis_double(fec_reconstruct_finished - reconstruct_start), to_millis_double(block_finalized - fec_reconstruct_finished), to_millis_double(process_start - block_finalized), to_millis_double(std::chrono::steady_clock::now() - process_start), fNewBlock);
                        if (fNewBlock) {
                            LogPrintf("UDP: Block %s had serialized size %lu\n", decoded_block.GetHash().ToString(), GetSerializeSize(decoded_block, PROTOCOL_VERSION));
                        }
                    }

                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    setBlocksReceived.insert(process_block.first);
                    RemovePartialBlocks(process_block.first.first); // Ensure we remove even if we didnt UDPRelayBlock()
                }
            } else if (!block.in_header && block.blk_initialized) {
                uint32_t mempool_provided_chunks = 0;
                uint32_t total_chunk_count = 0;
                uint256 blockHash;
                bool fDone = block.block_data.IsIterativeFillDone();
                while (!fDone) {
                    size_t firstChunkProcessed;
                    if (!lock)
                        lock.lock();
                    if (!total_chunk_count) {
                        total_chunk_count = block.block_data.GetChunkCount();
                        blockHash = block.block_data.GetBlockHash();
                    }
                    ReadStatus res = block.block_data.DoIterativeFill(firstChunkProcessed);
                    if (res != READ_STATUS_OK) {
                        lock.unlock();
                        std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                        if (res == READ_STATUS_INVALID) {
                            if (node == TRUSTED_PEER_DUMMY)
                                LogPrintf("UDP: Unable to process mempool for block %s from trusted peer(s), check your trusted peers are behaving well.\n", blockHash.ToString());
                            else {
                                LogPrintf("UDP: Unable to process mempool for block %s from %s, disconnecting\n", blockHash.ToString(), node.ToString());
                                const auto it = mapUDPNodes.find(node);
                                if (it != mapUDPNodes.end())
                                    DisconnectNode(it);
                            }
                        } else
                            LogPrintf("UDP: Unable to process mempool for block %s, dropping block\n", blockHash.ToString());
                        setBlocksReceived.insert(process_block.first);
                        RemovePartialBlock(process_block.first);
                        break;
                    } else {
                        while (firstChunkProcessed < total_chunk_count && block.block_data.IsChunkAvailable(firstChunkProcessed)) {
                            if (!block.body_decoder.HasChunk(firstChunkProcessed)) {
                                block.body_decoder.ProvideChunk(block.block_data.GetChunk(firstChunkProcessed), firstChunkProcessed);
                                mempool_provided_chunks++;
                            }
                            firstChunkProcessed++;
                        }

                        if (block.body_decoder.DecodeReady() || block.block_data.IsBlockAvailable()) {
                            block.is_decodeable = true;
                            more_work = true;
                            break;
                        }
                    }
                    fDone = block.block_data.IsIterativeFillDone();
                    if (!fDone && block.packet_awaiting_lock) {
                        lock.unlock();
                        std::this_thread::yield();
                    }
                }

                double chunk_hit_ratio = (double) mempool_provided_chunks / total_chunk_count;

                if (lock)
                    block.chunk_hit_ratio = chunk_hit_ratio;

                if (lock && !more_work)
                    lock.unlock();
                LogPrintf("UDP: Block %s - Initialized with %ld/%ld mempool-provided chunks (or more)\n", blockHash.ToString(), mempool_provided_chunks, total_chunk_count);
                LogPrint(BCLog::FEC, "UDP: Block %s - Chunk hit ratio: %f\n",
                         blockHash.ToString(), chunk_hit_ratio);
            }
        } while (more_work);
    }
}

void BlockRecvInit() {
    process_block_thread.reset(new std::thread(&TraceThread<void (*)()>, "udpprocess", &ProcessBlockThread));
}

void BlockRecvShutdown() {
    if (process_block_thread) {
        block_process_shutdown = true;
        block_process_cv.notify_all();
        process_block_thread->join();
        process_block_thread.reset();
    }
}

// TODO: Use the one from net_processing (with appropriate lock-free-ness)
static std::vector<std::pair<uint256, CTransactionRef>> udpnet_dummy_extra_txn;
ReadStatus PartialBlockData::ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header) {
    assert(in_header);
    in_header = false;
    return block_data.InitData(header, udpnet_dummy_extra_txn);
}

bool PartialBlockData::Init(const UDPMessage& msg) {
    assert((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS);
    const uint32_t obj_length  = msg.msg.block.obj_length;
    if (obj_length > MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR)
        return false;

    tip_blk = msg.header.msg_type & TIP_BLOCK;

    // When receiving a block at the tip of the blockchain, load FEC chunks
    // directly in memory. They are expected to remain there only briefly until
    // the block FEC-decoding completes. In contrast, if receiving non-tip
    // (repeated/historic) blocks, use the decoder in mmap mode so that FEC
    // chunks are offloaded to disk. The non-tip blocks can take a long time to
    // complete when many (thousands of) non-tip blocks are sent in parallel.
    const MemoryUsageMode memory_usage_mode = tip_blk ? MemoryUsageMode::USE_MEMORY : MemoryUsageMode::USE_MMAP;

    // In mmap mode, save chunks on a consistently-named file that persists
    // across bitcoind sessions. The name includes the two unique identifiers
    // used to map partial blocks in mapPartialBlocks: the peer (potentially a
    // "trusted peer") and the block hash prefix.
    std::string chunk_file_prefix = peer.ToString() + "_" + std::to_string(msg.msg.block.hash_prefix);

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER) {
        header_decoder = FECDecoder(
            obj_length,
            memory_usage_mode,
            chunk_file_prefix + "_header",
            true /* persist mmap file */
        );
        header_len = obj_length;
        header_initialized = true;
    } else {
        body_decoder = FECDecoder(
            obj_length,
            memory_usage_mode,
            chunk_file_prefix + "_body",
            true /* persist mmap file */
        );
        blk_len = obj_length;
        blk_initialized = true;
    }
    return true;
}

PartialBlockData::PartialBlockData(const CService& peer, const UDPMessage& msg, const std::chrono::steady_clock::time_point& packet_recv) :
        timeHeaderRecvd(packet_recv), peer(peer),
        in_header(true), blk_initialized(false), header_initialized(false),
        is_decodeable(false), is_header_processing(false),
        packet_awaiting_lock(false), awaiting_processing(false),
        chain_lookup(false), currentlyProcessing(false), blk_len(0),
        header_len(0), block_data(&mempool)
    {
       bool const ret = Init(msg);
       assert(ret);
    }

void PartialBlockData::ReconstructBlockFromDecoder() {
    assert(body_decoder.DecodeReady());

    for (uint32_t i = 0; i < DIV_CEIL(blk_len, sizeof(UDPBlockMessage::data)); i++) {
        if (!block_data.IsChunkAvailable(i)) {
            const void* data_ptr = body_decoder.GetDataPtr(i);
            assert(data_ptr);
            memcpy(block_data.GetChunk(i), data_ptr, sizeof(UDPBlockMessage::data));
            block_data.MarkChunkAvailable(i);
        }
    }

    assert(block_data.IsBlockAvailable());
};

/* Get FEC chunk senders corresponding to the partial block
 *
 * When "PartialBlockData.peer" is a "trusted peer", there can be multiple
 * senders aggregated in the same partial block. In this case, the multiple
 * senders can be obtained from the perNodeChunkCount map. In contrast, when
 * "PartialBlockData.peer" is a non-trusted peer, all chunks come from the same
 * peer. In this case, "PartialBlockData.peer" is the actual peer instead of a
 * dummy value.
 */
std::string PartialBlockData::GetSenders()
{
    if (peer != TRUSTED_PEER_DUMMY) {
        assert(perNodeChunkCount.size() == 1);
        return peer.ToString();
    }

    std::string senders;
    const size_t n_nodes = perNodeChunkCount.size();
    size_t i_node = 1;
    for (const auto& node : perNodeChunkCount) {
        senders += node.first.ToString();
        if (i_node++ < n_nodes)
            senders += ", ";
    }
    return senders;
}

static void BlockMsgHToLE(UDPMessage& msg) {
    msg.msg.block.hash_prefix = htole64(msg.msg.block.hash_prefix);
    msg.msg.block.obj_length  = htole32(msg.msg.block.obj_length);
    msg.msg.block.chunk_id    = htole32(msg.msg.block.chunk_id);
}

static bool HandleTx(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state) {
    if (msg.msg.block.obj_length > 400000) {
        LogPrintf("UDP: Got massive tx obj_length of %u\n", msg.msg.block.obj_length);
        return false;
    }

    if (state.tx_in_flight_hash_prefix != msg.msg.block.hash_prefix) {
        state.tx_in_flight_hash_prefix = msg.msg.block.hash_prefix;
        state.tx_in_flight_msg_size    = msg.msg.block.obj_length;
        state.tx_in_flight.reset(new FECDecoder(msg.msg.block.obj_length, MemoryUsageMode::USE_MEMORY));
        // NOTE: always place txn chunks directly in memory instead of disk. The
        // FEC decoding is expected to be quick in this case.
    }

    if (!state.tx_in_flight) return true; // Already finished decode

    if (state.tx_in_flight_msg_size != msg.msg.block.obj_length) {
        LogPrintf("UDP: Got inconsistent object length for tx %lu\n", msg.msg.block.hash_prefix);
        return true;
    }

    assert(!state.tx_in_flight->DecodeReady());

    if (!state.tx_in_flight->ProvideChunk(msg.msg.block.data, msg.msg.block.chunk_id)) {
        // Bad chunk id, maybe FEC is upset? Don't disconnect in case it can be random
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from tx %lu from %s\n", msg.msg.block.chunk_id, msg.msg.block.hash_prefix, node.ToString());
        return true;
    }

    if (state.tx_in_flight->DecodeReady()) {
        std::vector<unsigned char> tx_data = state.tx_in_flight->GetDecodedData();

        try {
            VectorInputStream stream(&tx_data, SER_NETWORK, PROTOCOL_VERSION);
            codec_version_t codec_version;
            stream >> *reinterpret_cast<std::uint8_t*>(&codec_version);
            CTransactionRef tx;
            stream >> CTxCompressor(tx, codec_version);
            LOCK(cs_main);
            CValidationState state;
            if (AcceptToMemoryPool(mempool, state, tx, nullptr, nullptr, false, 0)) {
                RelayTransaction(tx->GetHash(), *g_connman);
            }
        } catch (std::exception& e) {
            LogPrintf("UDP: Tx decode failed for tx %lu from %s: %s\n", msg.msg.block.hash_prefix, node.ToString(), e.what());
        }

        state.tx_in_flight.reset();
    }

    return true;
}

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const int sockfd) {
    //TODO: There are way too many damn tree lookups here...either cut them down or increase parallelism
    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    assert((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_TX_CONTENTS);

    if (length != sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage)) {
        LogPrintf("UDP: Got invalidly-sized (%d bytes) message from %s\n", length, node.ToString());
        return false;
    }

    msg.msg.block.hash_prefix = le64toh(msg.msg.block.hash_prefix);
    msg.msg.block.obj_length  = le32toh(msg.msg.block.obj_length);
    msg.msg.block.chunk_id    = le32toh(msg.msg.block.chunk_id);

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_TX_CONTENTS)
        return HandleTx(msg, length, node, state);

    const bool is_blk_header_chunk  = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER;
    const bool is_blk_content_chunk = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS;
    const bool they_have_block      = msg.header.msg_type & HAVE_BLOCK;
    const bool empty_block          = msg.header.msg_type & EMPTY_BLOCK; // a block that comes entirely through the header

    const uint64_t hash_prefix = msg.msg.block.hash_prefix; // Need a reference in a few places, but its packed, so we can't have one directly
    CService peer              = state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node;
    const std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(hash_prefix, peer);

    if (msg.msg.block.obj_length > MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR) {
        LogPrintf("UDP: Got massive obj_length of %u\n", msg.msg.block.obj_length);
        return false;
    }

    // Number of chunks that the data object (before FEC enconding) would occupy
    const size_t n_chunks = DIV_CEIL(msg.msg.block.obj_length, sizeof(UDPBlockMessage::data));

    if (setBlocksRelayed.count(msg.msg.block.hash_prefix) || setBlocksReceived.count(hash_peer_pair))
        return true;

    std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = state.chunks_avail.find(msg.msg.block.hash_prefix);

    if (chunks_avail_it == state.chunks_avail.end()) {
        if (is_blk_header_chunk) {
            if (state.chunks_avail.size() > 1 && !state.connection.fTrusted) {
                // Non-trusted nodes can only be forwarding up to 2 blocks at a time
                assert(state.chunks_avail.size() == 2);
                auto first_partial_block_it  = mapPartialBlocks.find(std::make_pair(state.chunks_avail. begin()->first, node));
                assert(first_partial_block_it != mapPartialBlocks.end());
                auto second_partial_block_it = mapPartialBlocks.find(std::make_pair(state.chunks_avail.rbegin()->first, node));
                assert(second_partial_block_it != mapPartialBlocks.end());
                if (first_partial_block_it->second->timeHeaderRecvd < second_partial_block_it->second->timeHeaderRecvd) {
                    state.chunks_avail.erase(first_partial_block_it->first.first);
                    mapPartialBlocks.erase(first_partial_block_it);
                } else {
                    state.chunks_avail.erase(second_partial_block_it->first.first);
                    mapPartialBlocks.erase(second_partial_block_it);
                }
            }
        }

        /* NOTE: once we add to chunks_avail, we MUST add to
         * PartialBlockData.perNodeChunkCount, or we will leak memory.
         *
         * This is mostly because chunks_avail is a state that is kept per node,
         * whereas perNodeChunkCount is kept per partial block. When the
         * decoding of a partial block is completed, function RemovePartialBlock
         * is called and the partial block is provided as argument. This
         * function, then, iterates over all nodes that are present in
         * PartialBlockData.perNodeChunkCount (nodes that delivered chunks of
         * the partial block) and, for each node, it erases the corresponding
         * entry (with the hash of the given block as key) from the chunks_avail
         * maps. Hence, the node must be registered in perNodeChunkCount in
         * order for the erasing from chunks_avail to work.
         */
        chunks_avail_it = state.chunks_avail.emplace(std::piecewise_construct,
                                                     std::forward_as_tuple(hash_prefix),
                                                     std::forward_as_tuple(they_have_block, n_chunks, is_blk_header_chunk)
            ).first;
    }

    if (they_have_block)
        chunks_avail_it->second.SetAllAvailable();
    else {
        // By calling Set*ChunkAvailable before SendMessageToNode's
        // SetHeaderDataAndFECChunkCount call, we will miss the first block packet we
        // receive and re-send that in UDPRelayBlock...this is OK because we'll save
        // more by doing this before the during-process relay below
        chunks_avail_it->second.SetChunkAvailable(msg.msg.block.chunk_id, n_chunks, is_blk_content_chunk);
    }

    bool new_block = false;
    auto it = mapPartialBlocks.find(hash_peer_pair);
    if (it == mapPartialBlocks.end()) {
        it = mapPartialBlocks.insert(std::make_pair(hash_peer_pair, std::make_shared<PartialBlockData>(peer, msg, packet_process_start))).first;
        new_block = true;
    }
    PartialBlockData& block = *it->second;

    std::chrono::steady_clock::time_point maps_scanned;
    if (fBench)
        maps_scanned = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> block_lock(block.state_mutex, std::try_to_lock);

    if ((is_blk_content_chunk && (block.is_decodeable || block.currentlyProcessing)) || // condition 1
        (is_blk_header_chunk && block.is_header_processing) || // condition 2
        (is_blk_header_chunk && !block.in_header)) { // condition 3
        /*
         * It seems this chunk isn't necessary, so it will be dropped. Yet, the
         * fact that we are here indicates that the block has not been processed
         * yet (setBlocksRelayed and setBlocksReceived don't have the block
         * yet). Thus, while the block is processing in ProcessNewBlockThread,
         * we continue forwarding chunks received from trusted peers.
         *
         * Note the conditions that lead to dropping:
         *
         * - Condition 1: We are already processing or ready to decode and
         *   process the block, so block content chunks are no longer necessary.
         *
         * - Condition 2: We know the header is already decodable, so further
         *   header FEC chunks are no longer necessary.
         *
         * - Condition 3: The header has already been decoded (ProvideHeaderData
         *   was called), so header chunks are no longer useful for decoding.
         */
        if (state.connection.fTrusted) {
            BlockMsgHToLE(msg);
            if (block.is_decodeable || block.currentlyProcessing)
                msg.header.msg_type |= HAVE_BLOCK;
            else
                msg.header.msg_type &= ~HAVE_BLOCK;
            // We didn't need this chunk, call it low priority assuming our
            // peers didn't as well
            SendMessageToAllNodes(msg, length, false, hash_prefix);
        }
    }

    if (!block_lock) {
        block.packet_awaiting_lock = true;
        block_lock.lock();
        block.packet_awaiting_lock = false;
    }

    auto perNodeChunkCountIt =
        block.perNodeChunkCount.insert(std::make_pair(node, std::make_pair(0, 0))).first;
    perNodeChunkCountIt->second.second++;

    // Check one more time after finally locking. Maybe the state changed inside
    // ProcessBlockThread. If the conditions still indicate the chunk is
    // unnecessary, return now that we already registered the chunk on
    // perNodeChunkCount.
    if ((is_blk_content_chunk && (block.is_decodeable || block.currentlyProcessing)) || // condition 1
        (is_blk_header_chunk && block.is_header_processing) || // condition 2
        (is_blk_header_chunk && !block.in_header)) { // condition 3
        return true;
    }

    if ((is_blk_content_chunk && !block.blk_initialized) ||
        (is_blk_header_chunk && !block.header_initialized)) {
        if (!block.Init(msg)) {
            LogPrintf("UDP: Got block contents that couldn't match header for block id %lu\n", msg.msg.block.hash_prefix);
            return true;
        }

        /* If this is the first body chunk, and we've processed the header
         * already, we can kick off the processing whereby the the erasures of
         * the FEC-coded block are filled based on mempool txns. This processing
         * will start as long as !block.in_header && block.blk_initialized when
         * the PartialBlockData queued in block_process_queue is finally
         * processed. Otherwise, it won't start. Also, if the header is still
         * waiting on the block_process_queue to be processed, the
         * erasure-filling process will start automatically right after the
         * header processing, now that we have the first body chunk (i.e.,
         * block.blk_initialized). In this case, we don't even need to push the
         * block into the processing queue again (and we won't given that
         * awaiting_processing would still be true in this case). Importantly,
         * note the scan is only useful for new (relayed) blocks inserted on the
         * tip of the chain. Further notes below. */
        if (is_blk_content_chunk && block.tip_blk && !block.awaiting_processing) {
            block.awaiting_processing = true;
            DoBackgroundBlockProcessing(*it); // Kick off mempool scan (waits on us to unlock block_lock)
        }
    }

    FECDecoder& decoder = is_blk_header_chunk ? block.header_decoder : block.body_decoder;

    if ((is_blk_header_chunk && (msg.msg.block.obj_length != block.header_len)) ||
        (is_blk_content_chunk && (msg.msg.block.obj_length != block.blk_len))) {
        // Duplicate hash_prefix or bad trusted peer
        LogPrintf("UDP: Got wrong obj_length/chunsk_sent for block id %lu from peer %s! Check your trusted peers are behaving well\n", msg.msg.block.hash_prefix, node.ToString());
        return true;
    }

    if (decoder.HasChunk(msg.msg.block.chunk_id)) {
        /* We are probably receiving a repeated chunk while the block is not
         * decodable yet. This is typical (and acceptable) when receiving from
         * multiple peers, especially for the initial uncoded chunks that are
         * sent by all peers through SendLimitedDataChunks. */
        return true;
    }

    if (is_blk_content_chunk && !block.in_header && msg.msg.block.chunk_id < block.block_data.GetChunkCount()) {
        /* If in_header is true, ProvideHeaderData has not be called yet, which
         * means PartiallyDownloadedChunkBlock::InitData also has not been
         * called yet and, hence, chunksAvailable has not been resized. So
         * GetChunkCount() will fail. Thus, we check in_header before calling
         * GetChunkCount(). Also, this means we can't mark an uncoded chunk as
         * available yet. We can still feed it to the FEC decoder, though. And
         * FEC-coded chunks (chunk ids exceeding GetChunkCount()) are not
         * affected by this, as they are not marked as available.
         */
        assert(!block.block_data.IsChunkAvailable(msg.msg.block.chunk_id)); // HasChunk should have returned false, then
        memcpy(block.block_data.GetChunk(msg.msg.block.chunk_id), msg.msg.block.data, sizeof(UDPBlockMessage::data));
        block.block_data.MarkChunkAvailable(msg.msg.block.chunk_id);
    }

    if (!decoder.ProvideChunk(msg.msg.block.data, msg.msg.block.chunk_id)) {
        // Bad chunk id, maybe FEC is upset? Don't disconnect in case it can be random
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from block %lu from %s\n", msg.msg.block.chunk_id, msg.msg.block.hash_prefix, node.ToString());
        return true;
    }

    std::chrono::steady_clock::time_point chunks_processed;
    if (fBench)
        chunks_processed = std::chrono::steady_clock::now();

    // Keep track of chunks that are actually used for decoding
    perNodeChunkCountIt->second.first++;

    if (state.connection.fTrusted) {
        BlockMsgHToLE(msg);
        msg.header.msg_type &= ~HAVE_BLOCK;
        // We needed this chunk, call it high priority assuming our
        // peers will as well
        SendMessageToAllNodes(msg, length, true, hash_prefix);
    }

    if (decoder.DecodeReady()) {
        if (is_blk_header_chunk)
            block.is_header_processing = true;
        else
            block.is_decodeable = true;

        /* If this is a relayed block (from the tip of the chain), we kick-off
         * the processing of the FEC object as soon as it is ready, regardless
         * of which object it is. By doing so, if the header is the object that
         * is decoded first (the usual case), the ProcessBlockThread will
         * process the header immediately and prepare (reserved space for) the
         * chunk-coded block. Subsequently, as soon as the first body chunk
         * comes, the process thread will start to prefill the chunk-coded block
         * with txns from the mempool.
         *
         * In contrast, if this is a backfill block, we can wait until both
         * header and body FEC objects are ready to be decoded. If we pushed the
         * header right now, we would end up wasting a lot of memory with
         * reserved chunk-coded blocks that would not be prefilled (only tip
         * blocks are prefilled). In fact, the current implementation of the
         * ProcessBlockThread won't even allow this to happen. Nevertheless,
         * there are two main reasons to consider the early processing of a
         * non-tip block header:
         *
         * 1) We need to decode the header in order to find out if we already
         * have the corresponding block. If we do have the block already, we can
         * ignore subsequent chunks of the block and, with that, save
         * significant processing. We can push the header FEC object for
         * processing just so that the chain is looked up. After that, we can
         * wait until the body is decodable to process the header again.
         *
         * 2) If the backfill block has an empty "body", i.e. contains only the
         * coinbase txn, which comes in the header. Such empty blocks are sent
         * through the header only, in which case the header must be processed
         * as soon as ready.
         *
         * Note also that it's perfectly possible that we start receiving a
         * block from a tip block object, but fail to complete it, and then we
         * complete it based on the redundant (non-tip) block. From the tip
         * object, we could have completed either the header or the body
         * already. If we completed the header, we already processed it, as it
         * was processed immediately. So now we could be getting the body from a
         * non-tip block, and it's possible that flag block.is_header_processing
         * is false because the header has already been decoded, rather than
         * because it's not ready yet. So the missing piece is to check also
         * whether the header has already been processed (i.e. block.in_header
         * is false) when the body becomes decodable.
         *
         * To avoid confusion, instead of taking the "tip-block flag" from the
         * current packet, we always read it from the value initialized on the
         * partial block (i.e., block.tip_blk below). This way, the partial
         * block that started from a tip block remains like so.
         */
        if (!block.awaiting_processing &&
            (block.tip_blk ||
             (block.is_header_processing && (!block.chain_lookup || empty_block || block.is_decodeable)) ||
             (block.is_decodeable && !block.in_header)) // if for some reason we've processed the header of the non-tip block already
            ) {
            block.awaiting_processing = true;
            DoBackgroundBlockProcessing(*it);
        }

        // We do not RemovePartialBlock as we want ChunkAvailableSets to be there when UDPRelayBlock gets called
        // from inside ProcessBlockThread, so after we notify the ProcessNewBlockThread we cannot access block.
        block_lock.unlock();
    }

    if (fBench && new_block) {
        std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
        LogPrintf("UDP: Processed first block header chunk in %lf %lf %lf %lf\n", to_millis_double(start - packet_process_start), to_millis_double(maps_scanned - start), to_millis_double(chunks_processed - maps_scanned), to_millis_double(finished - chunks_processed));
    }

    return true;
}

void ProcessDownloadTimerEvents() {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (auto it = mapPartialBlocks.begin(); it != mapPartialBlocks.end();) {
        if (std::chrono::steady_clock::now() - it->second->timeHeaderRecvd > std::chrono::hours(36))
            it = RemovePartialBlock(it);
        else
            it++;
    }
    //TODO: Prune setBlocksRelayed and setBlocksReceived to keep lookups fast?
}

struct BlkChunkStats {
    int height = -1;
    size_t header_rcvd = 0;
    size_t header_expected = 0;
    size_t body_rcvd = 0;
    size_t body_expected = 0;
    double progress = 0.0;
};

struct ChunkStats {
    int min_height = std::numeric_limits<int>::max();
    int max_height = 0;
    size_t n_blks = 0;
    size_t n_chunks = 0;
    BlkChunkStats min_blk;
    BlkChunkStats max_blk;
};

BlkChunkStats GetBlkChunkStats(const PartialBlockData& b) EXCLUSIVE_LOCKS_REQUIRED(cs_mapUDPNodes) {
    BlkChunkStats s;
    s.height          = b.height;
    s.header_rcvd     = b.header_decoder.GetChunksRcvd();
    s.body_rcvd       = b.body_decoder.GetChunksRcvd();
    const bool h_init = b.header_initialized;
    const bool b_init = b.blk_initialized;
    s.header_expected = (h_init) ? b.header_decoder.GetChunkCount() : 0;
    s.body_expected   = (b_init) ? b.body_decoder.GetChunkCount() : 0;
    s.progress        = (h_init && b_init) ?
        100.0 * ((double) (s.header_rcvd + s.body_rcvd)) /
        (s.header_expected + s.body_expected) : 0.0;
    return s;
}

/* Convert block stats to JSON */
UniValue BlkChunkStatsToJSON(const BlkChunkStats& s) EXCLUSIVE_LOCKS_REQUIRED(cs_mapUDPNodes) {
        std::ostringstream h_stream;
        std::ostringstream b_stream;
        std::ostringstream p_stream;
        h_stream << s.header_rcvd << " / " << s.header_expected;
        b_stream << s.body_rcvd << " / " << s.body_expected;
        p_stream << std::setprecision(4) << s.progress << "%";

        UniValue info(UniValue::VOBJ);
        if (s.height != -1)
            info.pushKV("height", s.height);
        info.pushKV("header_chunks", h_stream.str());
        info.pushKV("body_chunks", b_stream.str());
        info.pushKV("progress", p_stream.str());
        return info;
}

/* Given a block height of interest, search if there is a partial block with
 * that height currently in memory and return the stats of that block in JSON */
UniValue BlkChunkStatsToJSON(const int target_height) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (const auto& b : mapPartialBlocks) {
        std::unique_lock<std::mutex> block_lock(b.second->state_mutex);
        const int height = b.second->height;
        if (height != -1 && height == target_height) {
            const BlkChunkStats s = GetBlkChunkStats(*b.second);
            return BlkChunkStatsToJSON(s);
        }
    }
    return UniValue::VNULL;
}

/* Return JSON with chunk stats of the current partial blocks with min and max height */
UniValue MaxMinBlkChunkStatsToJSON() {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    ChunkStats s;

    s.n_blks = mapPartialBlocks.size();

    for (const auto& b : mapPartialBlocks) {
        std::unique_lock<std::mutex> block_lock(b.second->state_mutex);
        const BlkChunkStats blk_s = GetBlkChunkStats(*b.second);
        s.n_chunks += blk_s.header_rcvd;
        s.n_chunks += blk_s.body_rcvd;

        if (blk_s.height == -1)
            continue;

        if (blk_s.height < s.min_height) {
            s.min_height = blk_s.height;
            s.min_blk    = blk_s;
        }

        if (blk_s.height > s.max_height) {
            s.max_height = blk_s.height;
            s.max_blk    = blk_s;
        }
    }

    UniValue ret(UniValue::VOBJ);
    if (s.min_height != std::numeric_limits<int>::max())
        ret.pushKV("min_blk", BlkChunkStatsToJSON(s.min_blk));

    if (s.max_height != 0)
        ret.pushKV("max_blk", BlkChunkStatsToJSON(s.max_blk));

    ret.pushKV("n_blks", s.n_blks);
    ret.pushKV("n_chunks", s.n_chunks);

    return ret;
}

/* Return JSON with chunk stats of all current partial blocks */
UniValue AllBlkChunkStatsToJSON() {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    UniValue o(UniValue::VOBJ);
    for (const auto& b : mapPartialBlocks) {
        std::unique_lock<std::mutex> block_lock(b.second->state_mutex);
        const uint64_t hash_prefix = b.first.first;
        char hex_hash_prefix[17];
        snprintf(hex_hash_prefix, sizeof(hex_hash_prefix), "%016lx", hash_prefix);
        const BlkChunkStats s = GetBlkChunkStats(*b.second);
        UniValue info       = BlkChunkStatsToJSON(s);
        o.__pushKV(hex_hash_prefix, info);
    }
    return o;
}

/* Get the most recent FEC hit ratios: the chunk and txn hit ratios
 *
 * The ratio refers to the number FEC chunks or txns already available for
 * incoming compact blocks in relation to the total number of chunks or txns in
 * the block. */
UniValue FecHitRatioToJson() {
    UniValue ret(UniValue::VOBJ);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        if (it->second.last_txn_hit_ratio != -1 &&
            it->second.last_chunk_hit_ratio != -1) {
            UniValue info(UniValue::VOBJ);
            info.pushKV("txn_ratio", it->second.last_txn_hit_ratio);
            info.pushKV("chunk_ratio", it->second.last_chunk_hit_ratio);
            ret.__pushKV(it->first.ToString(), info);
        }
    }
    return ret;
}
