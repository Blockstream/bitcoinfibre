// Copyright (c) 2021 Blockstream
#ifndef BITCOIN_UDPMULTICASTTXDB_H
#define BITCOIN_UDPMULTICASTTXDB_H

#include <dbwrapper.h>

/**
 * @brief Key used to identify data saved on the UDP Multicast Tx database.
 */
struct UdpMulticastTxDbKey {
    uint16_t physical_idx;
    uint16_t logical_idx;
    mutable int height;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << physical_idx;
        s << logical_idx;
        s << height;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> physical_idx;
        s >> logical_idx;
        s >> height;
    }
};

class UdpMulticastTxDb
{
private:
    const UdpMulticastTxDbKey m_key;

    /**
     * @brief Get the key for the next database operation
     * @param height Target block height.
     * @return const UdpMulticastTxDbKey& reference to key object.
     */
    const UdpMulticastTxDbKey& GetKey(int height);

public:
    /**
     * @brief Construct a new UDP Multicast Tx Db object
     *
     * @param physical_idx Physical index of the UDP Multicast Tx stream.
     * @param logical_idx Logical index of the UDP Multicast Tx stream.
     */
    UdpMulticastTxDb(uint16_t physical_idx, uint16_t logical_idx);

    /**
     * @brief Construct a new UDP Multicast Tx Db object
     *
     * @param idx_pair Pair with the physical and logical indexes of the UDP
     * Multicast Tx stream.
     */
    UdpMulticastTxDb(const std::pair<uint16_t, uint16_t>& idx_pair);

    /**
     * @brief Get the block transmission progress
     *
     * @param[in] height Target block height.
     * @param[out] idx Next FEC chunk index to transmit.
     * @return true  If the progress was ready successfully.
     * @return false If there was a failure when reading from the database.
     */
    bool GetBlockProgress(int height, size_t& idx);

    /**
     * @brief Set the block transmission progress
     *
     * @param[in] height Target block height.
     * @param[in] new_idx Next FEC chunk index to transmit.
     * @return true  If the progress was saved successfully.
     * @return false If there was a failure when writing to the database.
     */
    bool SetBlockProgress(int height, size_t new_idx);

    /**
     * @brief Erase block from the database.
     *
     * @param height Target block height.
     * @return true  If the block was erased successfully.
     * @return false If the operation failed.
     */
    bool EraseBlock(int height);

    /**
     * @brief Get the progress of all blocks in transmission by this stream
     *
     * This object controls the state of a single UDP Multicast Tx stream
     * identified by its physical and logical indexes. Correspondingly, this
     * function fetches the transmission progress of the blocks belonging to
     * this particular stream only.
     *
     * @return const std::map<int, size_t> Map with the height (int) and the
     * next chunk index (size_t) to be transmitted for all blocks currently in
     * transmission within this stream.
     */
    const std::map<int, size_t> GetBlockProgressMap();
};

/**
 * @brief Reset the database for testing purposes
 */
void ResetUdpMulticastTxDb();

#endif