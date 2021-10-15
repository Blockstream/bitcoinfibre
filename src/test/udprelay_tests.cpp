#include <bench/data/block413567.raw.h>
#include <boost/test/unit_test.hpp>
#include <chainparams.h>
#include <fec.h>
#include <miner.h>
#include <outoforder.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <udprelay.h>
#include <util/system.h>

namespace udprelay_tests {

struct TestBlock {
    CBlock block;
    int height;
    uint256 hash;
    uint64_t hash_prefix;
    std::pair<uint64_t, CService> hash_peer_pair;
    TestBlock() = default;
    TestBlock(CBlock&& block, const CService& peer, int height) : block(std::move(block)),
                                                                  height(height),
                                                                  hash(block.GetHash()),
                                                                  hash_prefix(hash.GetUint64(0)),
                                                                  hash_peer_pair(std::make_pair(hash_prefix, peer)) {}
};

struct UdpRelayTestingSetup : public RegTestingSetup {
    UDPConnectionState m_conn_state;
    CService m_peer;        // defaults to trusted peer
    TestBlock m_test_block; // defaults to empty block w/ coinbase only

    UdpRelayTestingSetup() : m_peer(GetTrustedPeer())
    {
        InitFec();
        ResetOoOBlockDb(); // Reset the OOOB database every time since the datadir changes
        SetDefaultTestBlock();
    }

    ~UdpRelayTestingSetup()
    {
        // Reset the state of setBlocksReceived so that the same hash prefix can
        // be fed again on a new test case
        ResetPartialBlockState();
    }

    void SetDefaultTestBlock()
    {
        // Generate an empty block (with the coinbase txn only) succeeding the
        // genesis block
        auto prev = m_node.chainman->ActiveTip();
        CScript script_pubkey;
        script_pubkey << 1 << OP_TRUE;
        const CChainParams& chainparams = Params();
        auto pblocktemplate = BlockAssembler(m_node.chainman->ActiveChainstate(), *m_node.mempool, chainparams).CreateNewBlock(script_pubkey);
        CBlock& block = pblocktemplate->block;
        block.hashPrevBlock = prev->GetBlockHash();
        block.nTime = prev->nTime + 1;
        int height = prev->nHeight + 1;

        // IncrementExtraNonce creates a valid coinbase and merkleRoot
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, prev, extraNonce);

        while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus()))
            ++block.nNonce;

        m_test_block = TestBlock(std::move(block), m_peer, height);
    }

    void SetTestBlock413567()
    {
        // Block 413567 is representative of a large block with many txns
        const std::vector<uint8_t> block413567{std::begin(block413567_raw), std::end(block413567_raw)};
        CBlock block;
        CDataStream stream(block413567, SER_NETWORK, PROTOCOL_VERSION);
        stream >> block;
        int height = 413567;
        m_test_block = TestBlock(std::move(block), m_peer, height);
    }

    void HandleBlockMessage(UDPMessage& msg)
    {
        std::chrono::steady_clock::time_point timestamp(std::chrono::steady_clock::now());
        HandleBlockTxMessage(msg, (sizeof(UDPMessage) - 1), m_peer, m_conn_state, timestamp, &m_node);
    }
};
} // namespace udprelay_tests

BOOST_AUTO_TEST_SUITE(udprelay_tests)

// Test decoding an empty block using the header FEC object only
BOOST_FIXTURE_TEST_CASE(test_empty_block_decoding, UdpRelayTestingSetup)
{
    // Generate the UDP messages with the FEC chunks
    FecOverhead overhead{10, 0};
    std::vector<UDPMessage> msgs;
    UDPFillMessagesFromBlock(m_test_block.block, msgs, m_test_block.height, overhead);

    // All generated messages should flag that the underlying block is empty
    for (size_t i = 0; i < msgs.size(); i++)
        BOOST_CHECK(IS_EMPTY_BLOCK(msgs[i]));

    // An empty block is encoded by the header FEC object only
    BOOST_CHECK_EQUAL(msgs.size(), 1 + overhead.fixed);

    // An empty block is encoded using repetition coding. Hence, a single chunk
    // should suffice to decode the full block
    HandleBlockMessage(msgs[0]);

    // The body should not become decodable because an empty block does not have
    // a body FEC object. In contrast, the header should be ready.
    auto partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block->is_header_processing);
    BOOST_CHECK(!partial_block->is_decodeable);

    // The block processing routine should decode the block and update the tip
    ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_test_block.hash, m_node.chainman->ActiveTip()->GetBlockHash());
    }

    // After being processed, the block should be removed from the partial block data map
    partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block == nullptr);

    // Also, if later the peer resends this block, the UDP message handler
    // should reject the chunks, as this hash-peer pair should already be
    // present on the "setBlocksReceived" set.
    HandleBlockMessage(msgs[1]);
    partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block == nullptr);
}

// Test decoding a historic (non-tip) out-of-order block (OOOB) in normal
// header/body order (header object fed first)
BOOST_FIXTURE_TEST_CASE(test_non_tip_ooob_decoding, UdpRelayTestingSetup)
{
    // Test block - large block with many txns
    SetTestBlock413567();

    // Generate the UDP messages with the FEC chunks
    FecOverhead overhead{10, 0};
    std::vector<UDPMessage> msgs;
    UDPFillMessagesFromBlock(m_test_block.block, msgs, m_test_block.height, overhead);

    // The test block is large enough such that the body is encoded by the
    // wirehair FEC scheme and the header by cm256
    int n_header_msgs = 0;
    int n_body_msgs = 0;
    for (size_t i = 0; i < msgs.size(); i++) {
        if (IS_BLOCK_HEADER_MSG(msgs[i]))
            n_header_msgs++;
        else
            n_body_msgs++;
    }
    BOOST_CHECK(n_header_msgs > 2);
    BOOST_CHECK(n_body_msgs > CM256_MAX_CHUNKS);

    // Feed the header messages first so that the header object becomes
    // decodable while the body object remains pending.
    for (size_t i = 0; i < msgs.size(); i++) {
        if (IS_BLOCK_HEADER_MSG(msgs[i])) {
            HandleBlockMessage(msgs[i]);
        }
    }

    // Only the header should be decodable at this point
    auto partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block != nullptr);
    BOOST_CHECK(partial_block->is_header_processing);
    BOOST_CHECK(!partial_block->is_decodeable);

    // Call the block processing routine early just like the udprelay
    // implementation would to look up some block info (like the height) before
    // allocating memory for the full header data
    ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);
    BOOST_CHECK(partial_block->chain_lookup);
    BOOST_CHECK_EQUAL(partial_block->height, m_test_block.height);

    // Since this block is not a tip block, the header should not be fully
    // processed on this first call to ProcessBlock. It was only meant to
    // trigger the initial chain look-up.
    BOOST_CHECK(!partial_block->tip_blk);
    BOOST_CHECK(partial_block->is_header_processing);      // header processing still pending
    BOOST_CHECK(partial_block->block_data.IsHeaderNull()); // header data still unavailable

    // Next, feed the body messages
    for (size_t i = 0; i < msgs.size(); i++) {
        if (IS_BLOCK_CONTENTS_MSG(msgs[i])) {
            HandleBlockMessage(msgs[i]);
        }
    }

    // Now the partial block should be entirely decodable (header and body)
    BOOST_CHECK(partial_block->is_header_processing);
    BOOST_CHECK(partial_block->is_decodeable);

    // Call the block processing routine again just like udprelay would
    ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);

    // This time, the header data should be fully processed
    BOOST_CHECK(!partial_block->block_data.IsHeaderNull());
    BOOST_CHECK_EQUAL(partial_block->block_data.GetBlockHash(), m_test_block.hash);

    // And the final CBlock should be obtained after decoding the FEC objects.
    // Since the block is out of order (height 413567), but still minimally
    // valid, it should have been added to the OOOB database.
    BOOST_CHECK(CountOoOBlocks() > 0);

    // After being processed, the block should be removed from the partial block data map
    partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block == nullptr);

    // And if later the peer resends this block, the UDP message handler should
    // reject the chunks (hash-peer pair in setBlocksReceived)
    HandleBlockMessage(msgs[0]);
    partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block == nullptr);
}

// Test decoding an out-of-order block marked as a tip-of-the-chain block
BOOST_FIXTURE_TEST_CASE(test_tip_ooob_decoding, UdpRelayTestingSetup)
{
    // Test block - large block with many txns
    SetTestBlock413567();

    // Generate the UDP messages with the FEC chunks
    FecOverhead overhead{10, 0};
    std::vector<UDPMessage> msgs;
    UDPFillMessagesFromBlock(m_test_block.block, msgs, m_test_block.height, overhead);

    // Mark all chunks as coming from a tip block. UDPFillMessagesFromBlock()
    // does not add the tip flag, as it is designed for historic blocks, but it
    // is used here for convenience. In practice, a relay node transmits tip
    // chunks through the RelayChunks() function instead.
    for (size_t i = 0; i < msgs.size(); i++)
        msgs[i].header.msg_type |= TIP_BLOCK;

    // Feed the header messages so that the header FEC object becomes decodable
    for (size_t i = 0; i < msgs.size(); i++) {
        if (IS_BLOCK_HEADER_MSG(msgs[i])) {
            HandleBlockMessage(msgs[i]);
        }
    }

    // Only the header should be decodable at this point
    auto partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block != nullptr);
    BOOST_CHECK(partial_block->is_header_processing);
    BOOST_CHECK(!partial_block->is_decodeable);

    // Since this block is marked as a tip block, the ProcessBlock() routine
    // should fully decode the header data right in its first call
    ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);
    BOOST_CHECK(partial_block->tip_blk);
    BOOST_CHECK(partial_block->chain_lookup);                      // chain already looked up
    BOOST_CHECK_EQUAL(partial_block->height, m_test_block.height); // height obtained
    BOOST_CHECK(!partial_block->is_header_processing);             // header already processed
    BOOST_CHECK(!partial_block->block_data.IsHeaderNull());        // header data available

    // And since the header data has been processed already (ProvideHeaderData
    // was called), the block hash should be available
    BOOST_CHECK_EQUAL(partial_block->block_data.GetBlockHash(), m_test_block.hash);
}

// Test decoding a historic (non-tip) out-of-order block (OOOB) received from a
// non-trusted peer
BOOST_FIXTURE_TEST_CASE(test_non_tip_ooob_non_trusted_peer, UdpRelayTestingSetup)
{
    // Test block - large block with many txns
    SetTestBlock413567();
    FecOverhead overhead{10, 0};

    // An OOOB received from a non-trusted peer should not be saved to the OOOB database
    {
        in_addr ip_addr;
        inet_pton(AF_INET, "172.16.235.1", &ip_addr);
        unsigned short port = 4434;
        static CService non_trusted_peer(ip_addr, port);
        std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(m_test_block.hash_prefix, non_trusted_peer);

        // Generate the UDP messages containing chunks of the header and body FEC objects
        std::vector<UDPMessage> msgs;
        UDPFillMessagesFromBlock(m_test_block.block, msgs, m_test_block.height, overhead);

        // Feed all messages as the non-trusted peer
        for (size_t i = 0; i < msgs.size(); i++) {
            std::chrono::steady_clock::time_point timestamp(std::chrono::steady_clock::now());
            HandleBlockTxMessage(msgs[i], (sizeof(UDPMessage) - 1), non_trusted_peer, m_conn_state, timestamp, &m_node);
        }

        // Both header and body should be decodable
        auto partial_block = GetPartialBlockData(hash_peer_pair);
        BOOST_CHECK(partial_block != nullptr);
        BOOST_CHECK(partial_block->is_header_processing);
        BOOST_CHECK(partial_block->is_decodeable);

        ProcessBlock(m_node.chainman.get(), hash_peer_pair, *partial_block);
        BOOST_CHECK(CountOoOBlocks() == 0); // OOOB not saved
    }

    ResetPartialBlockState();

    // In contrast, an OOOB received from a trusted peer should be saved into
    // the OOOB database
    {
        std::vector<UDPMessage> msgs;
        UDPFillMessagesFromBlock(m_test_block.block, msgs, m_test_block.height, overhead);

        for (size_t i = 0; i < msgs.size(); i++) {
            HandleBlockMessage(msgs[i]);
        }

        auto partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
        BOOST_CHECK(partial_block != nullptr);
        BOOST_CHECK(partial_block->is_header_processing);
        BOOST_CHECK(partial_block->is_decodeable);

        ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);
        BOOST_CHECK(CountOoOBlocks() > 0); // OOOB saved
    }
}

// Test decoding a historic (non-tip) out-of-order block (OOOB) in reversed
// header/body order (body FEC object fed first)
BOOST_FIXTURE_TEST_CASE(test_non_tip_ooob_body_first, UdpRelayTestingSetup)
{
    // Test block - large block with many txns
    SetTestBlock413567();

    // Generate the UDP messages with the FEC chunks
    FecOverhead overhead{10, 0};
    std::vector<UDPMessage> msgs;
    UDPFillMessagesFromBlock(m_test_block.block, msgs, m_test_block.height, overhead);

    // Feed the body messages first
    for (size_t i = 0; i < msgs.size(); i++) {
        if (IS_BLOCK_CONTENTS_MSG(msgs[i])) {
            HandleBlockMessage(msgs[i]);
        }
    }

    // Only the body should be decodable at this point
    auto partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block != nullptr);
    BOOST_CHECK(!partial_block->is_header_processing);
    BOOST_CHECK(partial_block->is_decodeable);

    // At this stage, calling ProcessBlock would be useless as it can't produce
    // any results without the header info
    ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);
    BOOST_CHECK(!partial_block->chain_lookup);             // chain was not looked up
    BOOST_CHECK_EQUAL(partial_block->height, -1);          // height still uninitialized
    BOOST_CHECK(partial_block->block_data.IsHeaderNull()); // header data not available yet

    // ProcessBlock should not have changed the state either
    BOOST_CHECK(!partial_block->is_header_processing);
    BOOST_CHECK(partial_block->is_decodeable);

    // Next, feed the header messages
    for (size_t i = 0; i < msgs.size(); i++) {
        if (IS_BLOCK_HEADER_MSG(msgs[i])) {
            HandleBlockMessage(msgs[i]);
        }
    }

    // Now, both header and body should be ready to be decoded
    BOOST_CHECK(partial_block->is_header_processing);
    BOOST_CHECK(partial_block->is_decodeable);

    // ProcessBlock should process the header and block in one go
    ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);
    BOOST_CHECK(partial_block->chain_lookup);                      // chain looked up
    BOOST_CHECK_EQUAL(partial_block->height, m_test_block.height); // block height obtained
    BOOST_CHECK(!partial_block->block_data.IsHeaderNull());        // header available
    BOOST_CHECK_EQUAL(partial_block->block_data.GetBlockHash(), m_test_block.hash);

    // Verify the block was added to the out-of-order block db
    BOOST_CHECK(CountOoOBlocks() > 0);
}

// Test decoding a historic (non-tip) out-of-order block (OOOB) sent in uncompressed form
BOOST_FIXTURE_TEST_CASE(test_non_tip_ooob_uncompressed, UdpRelayTestingSetup)
{
    // Test block - large block with many txns
    SetTestBlock413567();

    // Generate the UDP FEC message carrying the block in uncompressed form
    FecOverhead overhead{10, 0};
    std::vector<UDPMessage> msgs;
    UDPFillMessagesFromBlock(m_test_block.block, msgs, m_test_block.height, overhead, codec_version_t::none);

    // Make sure the uncompressed chunks really differ from the
    // default-generated chunks (compressed by the default codec)
    {
        std::vector<UDPMessage> compressed_msgs;
        UDPFillMessagesFromBlock(m_test_block.block, compressed_msgs, m_test_block.height, overhead);
        BOOST_CHECK(msgs.size() != compressed_msgs.size());
    }

    // Feed all FEC messages
    for (size_t i = 0; i < msgs.size(); i++) {
        HandleBlockMessage(msgs[i]);
    }

    // Both header and body should be decodable
    auto partial_block = GetPartialBlockData(m_test_block.hash_peer_pair);
    BOOST_CHECK(partial_block != nullptr);
    BOOST_CHECK(partial_block->is_header_processing);
    BOOST_CHECK(partial_block->is_decodeable);

    // ProcessBlock should ultimately add the block to the OOOB database
    ProcessBlock(m_node.chainman.get(), m_test_block.hash_peer_pair, *partial_block);
    BOOST_CHECK(CountOoOBlocks() > 0);
}

BOOST_AUTO_TEST_CASE(test_ischunkfilerecoverable)
{
    ChunkFileNameParts cfp;
    BOOST_CHECK(!IsChunkFileRecoverable("_8080_1234_body_2000", cfp));              // missing ip
    BOOST_CHECK(!IsChunkFileRecoverable("256.16.235.1_8080_1234_body_2000", cfp));  // invalid ip
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_1234_body_2000", cfp));       // missing port
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_8080_body_2000", cfp));       // missing hash_prefix
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_8080_1234_2000", cfp));       // missing type
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_8080_1234_body_", cfp));      // missing length
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_8080-1234_body_2000", cfp));  // invalid delimiter
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_8080_abc_body_2000", cfp));   // invalid hash_prefix
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_8080_1234_test_2000", cfp));  // invalid type
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235.1_8080_1234_body_g2000", cfp)); // invalid length
    BOOST_CHECK(!IsChunkFileRecoverable("172.16.235:1_8080_1234_body_2000", cfp));  // previous valid format (no longer supported)
    BOOST_CHECK(IsChunkFileRecoverable("172.16.235.1_8080_1234_body_2000", cfp));   // valid case
    BOOST_CHECK(cfp.ipv4Addr.s_addr == 32182444 && cfp.port == 8080 && cfp.hash_prefix == 1234 && cfp.is_header == false && cfp.length == 2000);
    BOOST_CHECK(IsChunkFileRecoverable("172.16.235.1_9560_12345678_header_2097152", cfp)); // valid case
    BOOST_CHECK(cfp.ipv4Addr.s_addr == 32182444 && cfp.port == 9560 && cfp.hash_prefix == 12345678 && cfp.is_header == true && cfp.length == 2097152);
    BOOST_CHECK(IsChunkFileRecoverable("0.0.0.0_0_12345678_header_10000", cfp)); // valid case (trusted peer)
}

BOOST_FIXTURE_TEST_CASE(test_recovery_invalid_files_get_removed, BasicTestingSetup)
{
    std::string obj_id1 = "172.16.235.1_8080_1234_body";

    FECDecoder decoder1(FEC_CHUNK_SIZE * 2, MemoryUsageMode::USE_MMAP, obj_id1);
    FECDecoder decoder2(FEC_CHUNK_SIZE * 2, MemoryUsageMode::USE_MMAP);
    FECDecoder decoder3(FEC_CHUNK_SIZE * 2, MemoryUsageMode::USE_MMAP, "1234_body");

    // Assume the application was aborted/closed, leaving partial block data in
    // disk. Next, reload the partial blocks, as if relaunching the application.
    LoadPartialBlocks(nullptr);

    // Given that decoder1 is the only decoder applying the chunk file naming
    // convention expected by the udprelay logic (more specifically by
    // IsChunkFileRecoverable()), the expectation is that decoder1's FEC data is
    // successfully reloaded after calling "LoadPartialBlocks", in which case
    // its chunk file remains. In contrast, the chunk files from decoder2 and
    // decoder3 shall be considered non-recoverable and removed by
    // LoadPartialBlocks().
    BOOST_CHECK(fs::exists(decoder1.GetFileName()));
    BOOST_CHECK(!fs::exists(decoder2.GetFileName()));
    BOOST_CHECK(!fs::exists(decoder3.GetFileName()));

    // cleanup mapPartialBlocks
    ResetPartialBlocks();
}

BOOST_FIXTURE_TEST_CASE(test_recovery_handles_body_and_header, BasicTestingSetup)
{
    // Define a hash prefix and peer address
    char ip_addr[INET_ADDRSTRLEN] = "172.16.235.1";
    const uint64_t hash_prefix = 1234;
    unsigned short port = 8080;

    struct in_addr ipv4Addr;
    inet_pton(AF_INET, ip_addr, &(ipv4Addr));
    CService peer(ipv4Addr, port);

    // Construct two decoders for the same hash prefix, one for the header data,
    // the other for body data. Persist the chunk files in disk.
    size_t n_body_chunks = 5;
    size_t n_header_chunks = 2;
    std::string chunk_file_prefix = peer.ToStringIP() + "_" + peer.ToStringPort() + "_" + std::to_string(hash_prefix);
    std::string obj_id1 = chunk_file_prefix + "_body";
    std::string obj_id2 = chunk_file_prefix + "_header";
    {
        const bool keep_mmap_file = true;
        FECDecoder decoder1(FEC_CHUNK_SIZE * n_body_chunks, MemoryUsageMode::USE_MMAP, obj_id1, keep_mmap_file);
        FECDecoder decoder2(FEC_CHUNK_SIZE * n_header_chunks, MemoryUsageMode::USE_MMAP, obj_id2, keep_mmap_file);
    }

    // Assume the application was aborted/closed, leaving partial block data in
    // disk. Next, reload the partial blocks, as if relaunching the application.
    auto partial_block_state = AllBlkChunkStatsToJSON();
    BOOST_CHECK(partial_block_state.size() == 0);

    LoadPartialBlocks(nullptr);

    // The body and header belonging to the same block (i.e., with the same hash
    // prefix) should not instantiate two distinct PartialBlockData objects. The
    // first FEC object (body or header) should instantiate the PartialBlockData
    // object, and the second FEC object should reuse the previous
    // PartialBlockData object while setting the proper data fields (header or
    // body decoder data). Hence, the expectation is that the data recovered
    // from decoder1 and decoder2 is succesfully loaded into the same
    // PartialBlockData object.
    partial_block_state = AllBlkChunkStatsToJSON();
    BOOST_CHECK(partial_block_state.size() == 1); // two decoders belonging to the same block insert only 1 PartialBlockData

    const std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(hash_prefix, peer);
    auto partial_block = GetPartialBlockData(hash_peer_pair);
    BOOST_CHECK(partial_block != nullptr);
    BOOST_CHECK(partial_block->blk_initialized);
    BOOST_CHECK(partial_block->header_initialized);
    BOOST_CHECK(partial_block->blk_len == FEC_CHUNK_SIZE * n_body_chunks);
    BOOST_CHECK(partial_block->header_len == FEC_CHUNK_SIZE * n_header_chunks);
    BOOST_CHECK(partial_block->body_decoder.GetFileName().filename().c_str() == obj_id1 + "_" + std::to_string(FEC_CHUNK_SIZE * n_body_chunks));
    BOOST_CHECK(partial_block->header_decoder.GetFileName().filename().c_str() == obj_id2 + "_" + std::to_string(FEC_CHUNK_SIZE * n_header_chunks));
    BOOST_CHECK(partial_block->body_decoder.GetChunkCount() == n_body_chunks);
    BOOST_CHECK(partial_block->header_decoder.GetChunkCount() == n_header_chunks);

    // cleanup mapPartialBlocks
    ResetPartialBlocks();
}

BOOST_FIXTURE_TEST_CASE(test_recovery_of_decodable_state, BasicTestingSetup)
{
    // Define a hash prefix and peer address
    char ip_addr[INET_ADDRSTRLEN] = "172.16.235.1";
    const uint64_t hash_prefix = 1234;
    unsigned short port = 8080;

    struct in_addr ipv4Addr;
    inet_pton(AF_INET, ip_addr, &(ipv4Addr));
    CService peer(ipv4Addr, port);

    // Construct two decoders for the same hash prefix, one for the header data,
    // the other for body data. Provide all the header chunks. Then, destroy the
    // decoders while persisting their chunk files in disk.
    std::vector<unsigned char> dummy_chunk(FEC_CHUNK_SIZE);
    size_t n_body_chunks = 5;
    size_t n_header_chunks = 2;
    std::string chunk_file_prefix = peer.ToStringIP() + "_" + peer.ToStringPort() + "_" + std::to_string(hash_prefix);
    std::string obj_id1 = chunk_file_prefix + "_body";
    std::string obj_id2 = chunk_file_prefix + "_header";
    {
        const bool keep_mmap_file = true;
        FECDecoder decoder1(FEC_CHUNK_SIZE * n_body_chunks, MemoryUsageMode::USE_MMAP, obj_id1, keep_mmap_file);
        FECDecoder decoder2(FEC_CHUNK_SIZE * n_header_chunks, MemoryUsageMode::USE_MMAP, obj_id2, keep_mmap_file);

        for (size_t chunk_id = 0; chunk_id < n_header_chunks; chunk_id++) {
            decoder2.ProvideChunk(dummy_chunk.data(), chunk_id);
        }
        BOOST_CHECK(!decoder1.DecodeReady());
        BOOST_CHECK(decoder2.DecodeReady());
    }

    // Assume the application was aborted/closed, leaving partial block data in
    // disk. Next, reload the partial blocks, as if relaunching the application.
    LoadPartialBlocks(nullptr);

    // The recovered partial block should indicate that its header is ready to
    // be processed/decoded, while the body is still not decodable.
    const std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(hash_prefix, peer);
    auto partial_block = GetPartialBlockData(hash_peer_pair);
    BOOST_CHECK(partial_block != nullptr);
    BOOST_CHECK(partial_block->is_header_processing);
    BOOST_CHECK(!partial_block->is_decodeable);

    // cleanup mapPartialBlocks
    ResetPartialBlocks();
}

BOOST_FIXTURE_TEST_CASE(test_recovery_multiple_blocks, BasicTestingSetup)
{
    size_t n_decoders = 2000;
    size_t n_body_chunks = 5;
    std::vector<std::unique_ptr<FECDecoder>> decoders_vec;

    // generate "n_decoders" unique hash_prefixes
    std::unordered_set<uint64_t> hash_prefixes_set;
    std::vector<uint64_t> hash_prefixes;
    while (hash_prefixes_set.size() < n_decoders)
        hash_prefixes_set.insert(1000 + (rand() % 10000));
    hash_prefixes.insert(hash_prefixes.end(), hash_prefixes_set.begin(), hash_prefixes_set.end());

    // Construct many decoders while persisting their chunk files in disk
    {
        const bool keep_mmap_file = true;
        for (size_t i = 0; i < n_decoders; i++) {
            std::string obj_id = "172.16.235.1_8080_" + std::to_string(hash_prefixes[i]) + "_body";
            decoders_vec.emplace_back(std::move(std::make_unique<FECDecoder>(FEC_CHUNK_SIZE * n_body_chunks, MemoryUsageMode::USE_MMAP, obj_id, keep_mmap_file)));
        }
    }

    // Assume the application was aborted/closed, leaving partial block data in
    // disk. Next, reload the partial blocks, as if relaunching the application.
    auto partial_block_state = AllBlkChunkStatsToJSON();
    BOOST_CHECK(partial_block_state.size() == 0);

    LoadPartialBlocks(nullptr);

    // All the previous decoders should be recovered
    partial_block_state = AllBlkChunkStatsToJSON();
    BOOST_CHECK(partial_block_state.size() == n_decoders);

    struct in_addr ipv4Addr;
    inet_pton(AF_INET, "172.16.235.1", &(ipv4Addr));
    CService peer(ipv4Addr, 8080);

    for (size_t i = 0; i < n_decoders; i++) {
        const std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(hash_prefixes[i], peer);
        auto partial_block = GetPartialBlockData(hash_peer_pair);
        BOOST_CHECK(partial_block != nullptr);
        BOOST_CHECK(partial_block->blk_initialized);
        BOOST_CHECK(!partial_block->header_initialized);
        BOOST_CHECK(partial_block->header_len == 0);
        BOOST_CHECK(partial_block->blk_len == FEC_CHUNK_SIZE * n_body_chunks);
        std::string obj_id = peer.ToStringIP() + "_" + peer.ToStringPort() + "_" + std::to_string(hash_prefixes[i]) + "_body";
        BOOST_CHECK(partial_block->body_decoder.GetFileName().filename().c_str() == obj_id + "_" + std::to_string(FEC_CHUNK_SIZE * n_body_chunks));
        BOOST_CHECK(partial_block->body_decoder.GetChunkCount() == n_body_chunks);
    }

    // cleanup mapPartialBlocks
    ResetPartialBlocks();
}

BOOST_AUTO_TEST_SUITE_END()
