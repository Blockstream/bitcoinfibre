// Copyright (c) 2020-2021 Blockstream
#ifndef BITCOIN_UDPMULTICASTTX_H
#define BITCOIN_UDPMULTICASTTX_H

#include <udpmulticasttxdb.h>
#include <udpnet.h>

struct BackfillBlock {
    mutable size_t idx = 0;       // index of the next message to be transmitted
    mutable std::mutex mutex;     // protects the access to idx
    std::vector<UDPMessage> msgs; // FEC messages
    BackfillBlock(size_t start_idx) : idx(start_idx){};
};

typedef std::map<int, BackfillBlock> BackfillBlockWindowMap;
typedef BackfillBlockWindowMap::iterator BackfillBlockWindowIt;
typedef BackfillBlockWindowMap::const_iterator BackfillBlockWindowConstIt;
typedef BackfillBlockWindowMap::value_type BackfillBlockWindowElement;

class BackfillBlockWindow
{
private:
    BackfillBlockWindowMap m_map; // window of backfill blocks
    std::mutex m_mutex;           // protects m_map
    uint64_t m_bytes_in_window = 0;
    std::pair<uint16_t, uint16_t> m_tx_idx; // Tx physical/logical index
    const bool m_save_progress;
    UdpMulticastTxDb m_db;

    BackfillBlockWindowIt Remove(BackfillBlockWindowConstIt it);

public:
    /**
     * @brief Construct a new Backfill Block Window object.
     *
     * @param tx_idx Pair with the physical and logical indexes identifying the
     * transmitter.
     * @param save_progress Whether to save the transmission progress via
     * UdpMulticastTxDb.
     */
    BackfillBlockWindow(std::pair<uint16_t, uint16_t> tx_idx, bool save_progress);

    /**
     * @brief Add block to transmission window.
     *
     * @param pindex Pointer to block to be added to the Tx window.
     * @param overhead FEC overhead to add on transmission.
     * @param start_idx Starting message index for transmission.
     *
     * @note By default, start_idx=0, which means the full BackfillBlock::msgs
     * vector is transmitted. In contrast, when resuming the transmission
     * initiated on a previous session, start_idx should be set to the index
     * where the previous session stopped.
     */
    void Add(const CBlockIndex* pindex, const FecOverhead& overhead, size_t start_idx = 0);

    /**
     * @brief Get the next message to be transmitted for a given block in the window.
     *
     * @param height Height of the target block within the block window.
     * @param block BackfillBlock object.
     * @return const UDPMessage& Next UDP message to transmit for the chosen block.
     */
    const UDPMessage& GetNextMsg(int height, const BackfillBlock& block);

    /**
     * @brief Remove any fully transmitted block from the block window.
     */
    void Cleanup();

    /**
     * @brief Return summarized window statistics in JSON format.
     *
     * The information includes the window size in bytes, the total number of
     * blocks in the window, the minimum and maximum block heights, and the
     * largest block currently in the window.
     *
     * @return UniValue Summarized window info.
     */
    UniValue ShortInfoToJSON();

    /**
     * @brief Return the complete window progress in JSON format.
     *
     * The JSON result includes the height of each block in the window, the
     * total number of UDP messages composing each block, and the index of the
     * next UDP message to be transmitted for each block.
     *
     * @return UniValue Full window info.
     */
    UniValue FullInfoToJSON();

    /**
     * @brief Get the block transmission window.
     *
     * @return const BackfillBlockWindowMap& Map with block heights as keys and
     * the corresponding BackfillBlock objects as values.
     */
    const BackfillBlockWindowMap& GetWindow() const
    {
        return m_map;
    }

    /**
     * @brief Get transmission window size in blocks.
     *
     * @return unsigned int How many blocks are currently in the transmission window.
     */
    unsigned int Size() const
    {
        return m_map.size();
    }
};

#endif