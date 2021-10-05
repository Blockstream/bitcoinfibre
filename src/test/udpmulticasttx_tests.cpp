#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <udpmulticasttx.h>
#include <validation.h>

namespace udpmulticasttx_tests {
struct UdpMulticastTxTestingSetup : public RegTestingSetup {
    UdpMulticastTxTestingSetup()
    {
        ResetUdpMulticastTxDb(); // Reset the database every time since the datadir changes
    }
};
} // namespace udpmulticasttx_tests

BOOST_FIXTURE_TEST_SUITE(udpmulticasttx_tests, UdpMulticastTxTestingSetup)

BOOST_AUTO_TEST_CASE(add_transmit_cleanup)
{
    const std::pair<uint16_t, uint16_t> tx_idx = std::make_pair(0, 0);
    const bool save_progress = false;
    BackfillBlockWindow block_window(tx_idx, save_progress);

    // The window (map) should be empty at this point
    const auto& map = block_window.GetWindow();
    BOOST_CHECK(map.empty());
    BOOST_CHECK(block_window.Size() == 0);

    // Add the tip (genesis) block to the Tx window
    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = m_node.chainman->ActiveTip();
        assert(pindex);
    }
    FecOverhead overhead{10, 0};
    block_window.Add(pindex, overhead);

    // The map should contain a block now
    int height = 0;
    BOOST_CHECK(!map.empty());
    BOOST_CHECK(block_window.Size() == 1);
    BOOST_CHECK(map.count(height) == 1);

    // Trying to clean up should not produce any effect at this point because
    // the block is not transmitted yet
    block_window.Cleanup();
    BOOST_CHECK(!map.empty());
    BOOST_CHECK(block_window.Size() == 1);
    BOOST_CHECK(map.count(height) == 1);

    // "Transmit" the windowed block completely
    for (const auto& block : map) {
        while (block.second.idx < block.second.msgs.size()) {
            block_window.GetNextMsg(block.first, block.second);
        }
    }

    // The transmission progress should not have been saved on the UDP Multicast
    // Tx database since save_progress=false
    UdpMulticastTxDb mcast_tx_db(tx_idx);
    const auto height_idx_map = mcast_tx_db.GetBlockProgressMap();
    BOOST_CHECK(height_idx_map.empty());

    // Clean up the transmitted block
    block_window.Cleanup();
    BOOST_CHECK(map.empty());
    BOOST_CHECK(block_window.Size() == 0);
}

BOOST_AUTO_TEST_CASE(save_tx_progress_on_db)
{
    // Tx parameters
    const std::pair<uint16_t, uint16_t> tx_idx = std::make_pair(0, 0);
    const bool save_progress = true;
    FecOverhead overhead{10, 0};
    unsigned int n_chunks_1st_session = 5;

    // Test block
    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = m_node.chainman->ActiveTip();
        assert(pindex);
    }

    // Assume two sessions of the UDP Multicast Tx application.

    // Session 1: transmit some chunks and exit
    {
        BackfillBlockWindow block_window(tx_idx, save_progress);

        // The UDP Multicast Tx database should be created on the datadir
        BOOST_CHECK(fs::exists(gArgs.GetDataDirNet() / "udp_multicast_tx"));

        // On startup, the database should be empty
        UdpMulticastTxDb mcast_tx_db(tx_idx);
        auto height_idx_map = mcast_tx_db.GetBlockProgressMap();
        BOOST_CHECK(height_idx_map.empty());

        // Add the test block to the Tx window
        block_window.Add(pindex, overhead);

        // Transmit "n_chunks_1st_session" chunks
        for (const auto& block : block_window.GetWindow()) {
            while (block.second.idx < n_chunks_1st_session) {
                block_window.GetNextMsg(block.first, block.second);
            }
        }

        // Verify the Tx progress database saves the correct state
        int height = 0;  // the test block is the genesis block
        size_t next_idx; // next index to be transmitted
        height_idx_map = mcast_tx_db.GetBlockProgressMap();
        BOOST_CHECK(height_idx_map.size() == 1);
        BOOST_CHECK(height_idx_map.count(height) == 1);
        mcast_tx_db.GetBlockProgress(height, next_idx);
        BOOST_CHECK(next_idx == n_chunks_1st_session);
    }

    // Assume the Tx application has terminated and is now relaunching.

    // Session 2: resume the Tx state and complete the block transmission.
    {
        BackfillBlockWindow block_window(tx_idx, save_progress);

        // The Tx window should be empty again
        BOOST_CHECK(block_window.Size() == 0);

        // In contrast, the Tx progress database should persist the state
        int height = 0;
        size_t next_idx;
        UdpMulticastTxDb mcast_tx_db(tx_idx);
        auto height_idx_map = mcast_tx_db.GetBlockProgressMap();
        BOOST_CHECK(height_idx_map.size() == 1);
        BOOST_CHECK(height_idx_map.count(height) == 1);
        mcast_tx_db.GetBlockProgress(height, next_idx);
        BOOST_CHECK(next_idx == n_chunks_1st_session);

        // Readd the same block while keeping the progress left from the previous session
        block_window.Add(pindex, overhead, next_idx);

        // Transmit the remaining chunks and clean up the Tx window
        const auto& map = block_window.GetWindow();
        for (const auto& block : map) {
            BOOST_CHECK(block.second.idx == n_chunks_1st_session);
            while (block.second.idx < block.second.msgs.size()) {
                block_window.GetNextMsg(block.first, block.second);
            }
        }
        block_window.Cleanup();
        BOOST_CHECK(map.empty());
        BOOST_CHECK(block_window.Size() == 0);

        // The corresponding entry should be removed from the Tx progress database
        height_idx_map = mcast_tx_db.GetBlockProgressMap();
        BOOST_CHECK(height_idx_map.empty());
    }
}

BOOST_AUTO_TEST_CASE(multiple_tx_streams)
{
    // Tx parameters
    const bool save_progress = true;
    FecOverhead overhead{10, 0};

    // Test block
    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = m_node.chainman->ActiveTip();
        assert(pindex);
    }

    // Add the test block to multiple Tx streams and "transmit" a distinct
    // number of chunks on each of them
    int height = 0; // the test block is the genesis block
    uint16_t n_streams = 4;
    size_t n_tx_chunks[4] = {2, 5, 3, 7}; // chunks to transmit on each stream
    for (uint16_t i = 0; i < n_streams; i++) {
        const std::pair<uint16_t, uint16_t> tx_idx = std::make_pair(i, 0);
        BackfillBlockWindow block_window(tx_idx, save_progress);
        block_window.Add(pindex, overhead);
        for (const auto& block : block_window.GetWindow()) {
            for (size_t j = 0; j < n_tx_chunks[i]; j++) {
                block_window.GetNextMsg(block.first, block.second);
            }
        }
    }

    // The Tx progress map obtained from the database should return the state of
    // the chosen Tx stream only
    for (uint16_t i = 0; i < n_streams; i++) {
        const std::pair<uint16_t, uint16_t> tx_idx = std::make_pair(i, 0);
        UdpMulticastTxDb mcast_tx_db(tx_idx);
        auto height_idx_map = mcast_tx_db.GetBlockProgressMap();
        BOOST_CHECK(height_idx_map.size() == 1);
        BOOST_CHECK(height_idx_map.count(height) == 1);
        size_t next_idx;
        mcast_tx_db.GetBlockProgress(height, next_idx);
        BOOST_CHECK(next_idx == n_tx_chunks[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()