// Copyright (c) 2020-2021 Blockstream
#include <chainparams.h>
#include <node/blockstorage.h>
#include <udpmulticasttx.h>
#include <udprelay.h>

BackfillBlockWindow::BackfillBlockWindow(std::pair<uint16_t, uint16_t> tx_idx,
                                         bool save_progress) : m_tx_idx(tx_idx),
                                                               m_save_progress(save_progress),
                                                               m_db(tx_idx){};

void BackfillBlockWindow::Add(const CBlockIndex* pindex, const FecOverhead& overhead, size_t start_idx)
{
    // Add an empty backfill block object to the protected block window map
    std::unique_lock window_lock(m_mutex);
    const auto res = m_map.emplace(std::piecewise_construct,
                                   std::forward_as_tuple(pindex->nHeight),
                                   std::forward_as_tuple(start_idx));

    // The given block height may already exist in the Tx window. for instance,
    // if the Tx loop is back on a block that is still in transmission.
    if (!res.second)
        return;

    // If not, proceed to fill the contents of this block
    const auto it = res.first;

    // Fetch the block from disk while the window mutex is unlocked (reading
    // from disk may take long)
    window_lock.unlock();
    CBlock block;
    assert(ReadBlockFromDisk(block, pindex, Params().GetConsensus()));
    const uint256 block_hash(block.GetHash());

    // Fill the FEC messages on the backfill block
    std::unique_lock block_lock(it->second.mutex);
    UDPFillMessagesFromBlock(block,
                             it->second.msgs,
                             pindex->nHeight,
                             overhead);
    if (m_save_progress) {
        m_db.SetBlockProgress(pindex->nHeight, it->second.idx);
    }
    block_lock.unlock();

    // Update the window size
    window_lock.lock();
    m_bytes_in_window += it->second.msgs.size() * FEC_CHUNK_SIZE;
    window_lock.unlock();

    LogPrint(BCLog::FEC, "UDP: Multicast Tx %lu-%lu - "
                         "fill block %s (%20lu) - height %7d - %5d chunks\n",
             m_tx_idx.first,
             m_tx_idx.second,
             block_hash.ToString(),
             block_hash.GetUint64(0),
             pindex->nHeight,
             it->second.msgs.size());
}

const UDPMessage& BackfillBlockWindow::GetNextMsg(int height, const BackfillBlock& block)
{
    std::lock_guard block_lock(block.mutex);
    assert(block.idx < block.msgs.size());
    const UDPMessage& msg = block.msgs[block.idx++];
    if (m_save_progress) {
        m_db.SetBlockProgress(height, block.idx);
    }
    // NOTE: the progress saved above is not perfect because GetNextMsg is
    // called when scheduling a chunk for transmission, not when the chunk is
    // actually transmitted over the socket. As a workaround, the packet
    // scheduler has to wait until all queued packets are effectively
    // transmitted before exiting when the program is terminated (see the
    // implementation of "do_send_messages()" at udpnet.cpp).
    return msg;
}

BackfillBlockWindowIt BackfillBlockWindow::Remove(BackfillBlockWindowConstIt it) EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
{
    size_t n_chunks = it->second.msgs.size();
    int height = it->first;
    m_bytes_in_window -= n_chunks * FEC_CHUNK_SIZE;
    if (m_save_progress) {
        m_db.EraseBlock(height);
    }
    return m_map.erase(it);
}

void BackfillBlockWindow::Cleanup()
{
    std::lock_guard<std::mutex> window_lock(m_mutex);
    for (auto it = m_map.cbegin(); it != m_map.cend();) {
        std::lock_guard<std::mutex> block_lock(it->second.mutex);
        if (it->second.idx == it->second.msgs.size()) {
            it = Remove(it);
        } else {
            ++it;
        }
    }
}

UniValue BackfillBlockWindow::ShortInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    std::lock_guard<std::mutex> window_lock(m_mutex);

    /* Find the minimum height, the maximum height, and the height corresponding
     * to the largest block */
    int min_height = std::numeric_limits<int>::max();
    int max_height = 0;
    size_t max_n_chunks = 0;
    int height_largest_block = -1;
    for (const auto& b : m_map) {
        if (b.first < min_height)
            min_height = b.first;

        if (b.first > max_height)
            max_height = b.first;

        if (b.second.msgs.size() > max_n_chunks) {
            max_n_chunks = b.second.msgs.size();
            height_largest_block = b.first;
        }
    }
    ret.pushKV("size", ((double)m_bytes_in_window / (1048576)));
    ret.pushKV("n_blks", (uint64_t)m_map.size());
    ret.pushKV("min", min_height);
    ret.pushKV("max", max_height);
    ret.pushKV("largest", height_largest_block);
    return ret;
}

UniValue BackfillBlockWindow::FullInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    std::lock_guard<std::mutex> window_lock(m_mutex);
    for (const auto& b : m_map) {
        std::lock_guard<std::mutex> block_lock(b.second.mutex);
        UniValue info(UniValue::VOBJ);
        info.pushKV("index", (uint64_t)b.second.idx);
        info.pushKV("total", (uint64_t)b.second.msgs.size());
        ret.__pushKV(std::to_string(b.first), info);
    }
    return ret;
}