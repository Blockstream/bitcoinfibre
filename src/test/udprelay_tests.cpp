#include <boost/test/unit_test.hpp>
#include <fec.h>
#include <test/util/setup_common.h>
#include <udprelay.h>
#include <util/system.h>

BOOST_AUTO_TEST_SUITE(udprelay_tests)

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
