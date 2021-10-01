#include <boost/test/unit_test.hpp>
#include <fec.h>
#include <memory>
#include <sys/mman.h>
#include <test/util/setup_common.h>
#include <util/system.h>

static const std::array<MemoryUsageMode, 2> memory_usage_modes{MemoryUsageMode::USE_MMAP, MemoryUsageMode::USE_MEMORY};

#define DIV_CEIL(a, b) (((a) + (b)-1) / (b))

constexpr size_t default_encoding_overhead = 10;

struct FecTestingSetup : public BasicTestingSetup {
    FecTestingSetup()
    {
        InitFec();
    }
    /**
     * The files generated within the partial_blocks directory during tests get
     * cleaned once the tests finish, but the directories stay. Thus, after a
     * while, "/tmp/test_common_Bitcoin Core" will be filled with useless empty
     * directories. The FecTestingSetup destructor runs after all the tests and
     * removes these directories.
     */
    ~FecTestingSetup()
    {
        fs::path partial_blocks = gArgs.GetDataDirNet() / "partial_blocks";
        fs::remove_all(partial_blocks.parent_path());
    }
};

struct TestData {
    std::vector<std::vector<unsigned char>> encoded_chunks;
    std::vector<uint32_t> chunk_ids;
    std::vector<unsigned char> original_data;
};

/**
 * Fills the input vector with random generated hex values
 */
void fill_with_random_data(std::vector<unsigned char>& vec)
{
    constexpr char hex_digits[] = "0123456789ABCDEF";

    auto rand_hex_gen = [&]() {
        auto h1 = hex_digits[(rand() % 16)];
        return h1;
    };
    std::generate(vec.begin(), vec.end(), rand_hex_gen);
}

std::string random_string(size_t len = 16)
{
    constexpr char chars[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::string s(len, '\0');

    auto rand_char_gen = [&]() {
        auto h1 = chars[(rand() % 62)];
        return h1;
    };
    std::generate(s.begin(), s.end(), rand_char_gen);
    return s;
}

/**
 * Generates some random data and encodes them using one of the encoders.
 * The function will fill in the input test_data parameter with
 * the encoded chunks as well as their chunk_ids and the original randomly
 * generated data to be used in tests.
 */
bool generate_encoded_chunks(size_t block_size, TestData& test_data, size_t n_overhead_chunks = 0)
{
    size_t n_uncoded_chunks = DIV_CEIL(block_size, FEC_CHUNK_SIZE);
    // wirehair wirehair is not maximum distance separable (MDS) and needs some extra chunks to recover the original data successfully
    size_t total_encoded_chunks = n_uncoded_chunks + n_overhead_chunks;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
                         std::forward_as_tuple(new FECChunkType[total_encoded_chunks]),
                         std::forward_as_tuple(total_encoded_chunks));

    test_data.original_data.resize(block_size);
    fill_with_random_data(test_data.original_data);

    FECEncoder block_encoder(&test_data.original_data, &block_fec_chunks);

    for (size_t vector_idx = 0; vector_idx < total_encoded_chunks; vector_idx++) {
        if (!block_encoder.BuildChunk(vector_idx)) {
            return false;
        }
        std::vector<unsigned char> fec_chunk(FEC_CHUNK_SIZE);
        memcpy(fec_chunk.data(), &block_fec_chunks.first[vector_idx], FEC_CHUNK_SIZE);
        test_data.encoded_chunks.emplace_back(fec_chunk);
        test_data.chunk_ids.emplace_back(block_fec_chunks.second[vector_idx]);
    }
    return true;
}

static void check_chunk_equal(const void* p_chunk1, std::vector<unsigned char>& chunk2)
{
    // Chunk1 is the chunk under test, whose size is always FEC_CHUNK_SIZE
    std::vector<unsigned char> chunk1(FEC_CHUNK_SIZE);
    memcpy(chunk1.data(), p_chunk1, FEC_CHUNK_SIZE);

    // Chunk2 represents the reference data that should be contained on
    // chunk1. Nevertheless, this data vector can occupy less than
    // FEC_CHUNK_SIZE.
    const size_t size = chunk2.size();
    BOOST_CHECK(size <= FEC_CHUNK_SIZE);

    // Compare the useful part of chunk1 (excluding zero-padding) against chunk2
    BOOST_CHECK_EQUAL_COLLECTIONS(chunk1.begin(), chunk1.begin() + size,
                                  chunk2.begin(), chunk2.end());

    // When chunk2's size is less than FEC_CHUNK_SIZE, the chunk under test
    // (chunk1) should be zero-padded. Check:
    if (size < FEC_CHUNK_SIZE) {
        const size_t n_padding = FEC_CHUNK_SIZE - size;
        std::vector<unsigned char> padding(n_padding, 0);
        BOOST_CHECK_EQUAL_COLLECTIONS(chunk1.begin() + size, chunk1.end(),
                                      padding.begin(), padding.end());
    }
}

static void check_chunk_not_equal(const void* p_chunk1, std::vector<unsigned char>& chunk2)
{
    // Compare the useful part of chunk1 (excluding zero-padding) against chunk2
    const size_t size = chunk2.size();
    std::vector<unsigned char> chunk1(size);
    memcpy(chunk1.data(), p_chunk1, size);
    // Find at least one mismatch in the vectors
    bool mismatch = false;
    for (size_t i = 0; i < size; i++) {
        if (chunk1[i] != chunk2[i]) {
            mismatch = true;
            break;
        }
    }
    BOOST_CHECK(mismatch);
}


BOOST_FIXTURE_TEST_SUITE(fec_tests, FecTestingSetup)

BOOST_AUTO_TEST_CASE(fec_test_buildchunk_invalid_idx)
{
    constexpr size_t n_uncoded_chunks = 5;
    constexpr size_t block_size = n_uncoded_chunks * FEC_CHUNK_SIZE;
    constexpr size_t n_encoded_chunks = n_uncoded_chunks + default_encoding_overhead;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
                         std::forward_as_tuple(new FECChunkType[n_encoded_chunks]),
                         std::forward_as_tuple(n_encoded_chunks));

    std::vector<unsigned char> original_data(block_size);
    fill_with_random_data(original_data);

    FECEncoder block_encoder(&original_data, &block_fec_chunks);

    // The valid chunk id range is within [0, n_encoded_chunks)
    BOOST_CHECK(block_encoder.BuildChunk(n_encoded_chunks - 1));
    BOOST_CHECK_THROW(block_encoder.BuildChunk(n_encoded_chunks), std::runtime_error);
    BOOST_CHECK_THROW(block_encoder.BuildChunk(n_encoded_chunks + 1), std::runtime_error);
}

void test_buildchunk_overwrite(size_t n_uncoded_chunks)
{
    size_t block_size = n_uncoded_chunks * FEC_CHUNK_SIZE;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
                         std::forward_as_tuple(new FECChunkType[n_uncoded_chunks]),
                         std::forward_as_tuple(n_uncoded_chunks));

    std::vector<unsigned char> original_data(block_size);
    fill_with_random_data(original_data);

    FECEncoder block_encoder(&original_data, &block_fec_chunks);

    // Generate one FEC chunk while keeping its chunk_id and data for future
    // comparison
    size_t vector_idx = 0;
    BOOST_CHECK(block_encoder.BuildChunk(vector_idx, false));
    uint32_t ref_chunk_id = block_fec_chunks.second[vector_idx];
    std::vector<unsigned char> ref_chunk_data(FEC_CHUNK_SIZE);
    memcpy(ref_chunk_data.data(), &block_fec_chunks.first[vector_idx], FEC_CHUNK_SIZE);

    // Build chunk again with overwrite = false
    BOOST_CHECK(block_encoder.BuildChunk(vector_idx, false));

    // expect chunk_id and data are untouched
    BOOST_CHECK_EQUAL(block_fec_chunks.second[vector_idx], ref_chunk_id);
    check_chunk_equal(&block_fec_chunks.first[vector_idx], ref_chunk_data);

    // Try again with overwrite = true
    BOOST_CHECK(block_encoder.BuildChunk(vector_idx, true));

    // in case of wirehair, the expectation is that both chunk_id and chunk data change
    // in case of cm256, the expectation is that neither chunk_id nor chunk data change
    if (n_uncoded_chunks > CM256_MAX_CHUNKS) {
        BOOST_CHECK(block_fec_chunks.second[vector_idx] != ref_chunk_id);
        check_chunk_not_equal(&block_fec_chunks.first[vector_idx], ref_chunk_data);
    } else {
        BOOST_CHECK_EQUAL(block_fec_chunks.second[vector_idx], ref_chunk_id);
        check_chunk_equal(&block_fec_chunks.first[vector_idx], ref_chunk_data);
    }
}

BOOST_AUTO_TEST_CASE(fec_test_buildchunk_overwrite_wirehair)
{
    test_buildchunk_overwrite(CM256_MAX_CHUNKS + 1);
}


BOOST_AUTO_TEST_CASE(fec_test_buildchunk_overwrite_cm256)
{
    test_buildchunk_overwrite(CM256_MAX_CHUNKS - 1);
}


BOOST_AUTO_TEST_CASE(fec_test_buildchunk_repetition_coding)
{
    // When the original data fits within a single chunk, repetition coding is used.
    constexpr size_t n_encoded_chunks = 3;
    constexpr size_t block_size = 10; // any number <= FEC_CHUNK_SIZE

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
                         std::forward_as_tuple(new FECChunkType[n_encoded_chunks]),
                         std::forward_as_tuple(n_encoded_chunks));

    std::vector<unsigned char> original_data(block_size);
    fill_with_random_data(original_data);

    FECEncoder block_encoder(&original_data, &block_fec_chunks);

    for (size_t vector_idx = 0; vector_idx < n_encoded_chunks; vector_idx++) {
        BOOST_CHECK(block_encoder.BuildChunk(vector_idx));

        // With repetition coding, the chunk_id is deterministic. It is equal to
        // the given vector_idx.
        BOOST_CHECK_EQUAL(block_fec_chunks.second[vector_idx], vector_idx);

        // Every encoded chunk should be equal to the original data when
        // repetition coding is used, aside from the padding.
        check_chunk_equal(&block_fec_chunks.first[vector_idx], original_data);
    }
}

BOOST_AUTO_TEST_CASE(fec_test_buildchunk_successful_Wirehair_encoder)
{
    // Choose block size bigger than CM256_MAX_CHUNKS to
    // force using wirehair encoder
    constexpr size_t n_uncoded_chunks = CM256_MAX_CHUNKS + 1;
    constexpr size_t block_size = n_uncoded_chunks * FEC_CHUNK_SIZE;
    TestData test_data;
    BOOST_CHECK(generate_encoded_chunks(block_size, test_data, default_encoding_overhead));
}

BOOST_AUTO_TEST_CASE(fec_test_buildchunk_successful_cm256_encoder)
{
    // Choose block size bigger than 1 chunk and smaller than
    // CM256_MAX_CHUNKS to force using cm256 encoder
    size_t block_size = FEC_CHUNK_SIZE + 1;
    TestData test_data;
    BOOST_CHECK(generate_encoded_chunks(block_size, test_data));
}


void test_fecdecoder_filename_pattern(size_t data_size)
{
    // Object ID provided:
    {
        std::string obj_id = random_string();
        FECDecoder decoder(data_size, MemoryUsageMode::USE_MMAP, obj_id);
        // filename should be set as "<obj_id>_<obj_size>"
        BOOST_CHECK_MESSAGE(decoder.GetFileName().filename().c_str() == obj_id + "_" + std::to_string(data_size), data_size);
    }
    // Object ID not provided:
    {
        FECDecoder decoder(data_size, MemoryUsageMode::USE_MMAP);
        // filename should be equal to the FECDecoder object's address
        BOOST_CHECK_MESSAGE(decoder.GetFileName().filename().c_str() == std::to_string(std::uintptr_t(&decoder)), data_size);
    }
}

BOOST_AUTO_TEST_CASE(fec_test_fecdecoder_filename_pattern)
{
    std::vector<size_t> data_sizes{FEC_CHUNK_SIZE + 1, 2000, FEC_CHUNK_SIZE * 2, 1048576};
    for (const auto data_size : data_sizes) {
        test_fecdecoder_filename_pattern(data_size);
    }
}

void test_providechunk_invalid_chunk_id(MemoryUsageMode memory_usage_mode)
{
    // Set data size in a way that CHUNK_COUNT_USES_CM256 is true
    constexpr size_t chunk_count = 2;
    constexpr size_t data_size = chunk_count * FEC_CHUNK_SIZE;
    std::vector<unsigned char> chunk(data_size);
    fill_with_random_data(chunk);

    FECDecoder decoder(data_size, memory_usage_mode);
    BOOST_CHECK_MESSAGE(!decoder.ProvideChunk(chunk.data(), 256), memory_usage_mode);

    // Set data size in a way that CHUNK_COUNT_USES_CM256 is false
    constexpr size_t chunk_count2 = CM256_MAX_CHUNKS + 1;
    constexpr size_t data_size2 = chunk_count2 * FEC_CHUNK_SIZE;
    std::vector<unsigned char> chunk2(data_size2);
    fill_with_random_data(chunk2);

    FECDecoder decoder2(data_size2, memory_usage_mode);
    BOOST_CHECK_MESSAGE(!decoder2.ProvideChunk(chunk2.data(), FEC_CHUNK_COUNT_MAX + 1), memory_usage_mode);
    BOOST_CHECK_MESSAGE(!decoder.DecodeReady(), memory_usage_mode);
}

BOOST_AUTO_TEST_CASE(fec_test_providechunk_invalid_chunk_id)
{
    for (const auto memory_usage_mode : memory_usage_modes) {
        test_providechunk_invalid_chunk_id(memory_usage_mode);
    }
}

void test_providechunk_small_chunk_count(MemoryUsageMode memory_usage_mode)
{
    // Generate random data fitting within a single chunk
    size_t data_size = 5;
    FECDecoder decoder(data_size, memory_usage_mode);
    std::vector<unsigned char> original_data(data_size);
    fill_with_random_data(original_data);

    // Corresponding zero-padded chunk
    std::vector<unsigned char> padded_chunk(original_data);
    padded_chunk.resize(FEC_CHUNK_SIZE, 0); // zero-padding

    // After providing the single chunk of data to the FEC decoder, the latter
    // should be ready to decode the message
    BOOST_CHECK_MESSAGE(decoder.ProvideChunk(padded_chunk.data(), 0), memory_usage_mode);
    BOOST_CHECK_MESSAGE(decoder.HasChunk(0), memory_usage_mode);
    BOOST_CHECK_MESSAGE(decoder.DecodeReady(), memory_usage_mode);

    // The original message should be entirely on the single chunk under test
    check_chunk_equal(decoder.GetDataPtr(0), original_data);
}

BOOST_AUTO_TEST_CASE(fec_test_providechunk_small_chunk_count)
{
    for (const auto memory_usage_mode : memory_usage_modes) {
        test_providechunk_small_chunk_count(memory_usage_mode);
    }
}

void providechunk_test(MemoryUsageMode memory_usage_type, size_t n_uncoded_chunks, bool expected_result, size_t n_overhead_chunks = 0, size_t n_dropped_chunks = 0)
{
    std::ostringstream check_msg;
    check_msg << "memory_usage_type = " << memory_usage_type << ", n_uncoded_chunks = " << n_uncoded_chunks << ", expected_result = " << expected_result << ", n_overhead_chunks = " << n_overhead_chunks << ", n_dropped_chunks = " << n_dropped_chunks;
    TestData test_data;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks;
    generate_encoded_chunks(data_size, test_data, n_overhead_chunks);

    size_t n_encoded_chunks = n_uncoded_chunks + n_overhead_chunks;

    // Randomly pick some indexes to be dropped
    // Make sure exactly n_dropped_chunks unique indexes are selected
    std::unordered_set<size_t> dropped_indexes;
    while (dropped_indexes.size() < n_dropped_chunks)
        dropped_indexes.insert(rand() % n_encoded_chunks);

    FECDecoder decoder(data_size, memory_usage_type);
    for (size_t i = 0; i < n_encoded_chunks; i++) {
        if (dropped_indexes.find(i) != dropped_indexes.end()) {
            // chunk i has been dropped
            continue;
        }
        decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }

    if (expected_result) {
        BOOST_CHECK_MESSAGE(decoder.DecodeReady(), check_msg.str());
        std::vector<unsigned char> decoded_data = decoder.GetDecodedData();
        BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
                                      test_data.original_data.begin(), test_data.original_data.end());
    } else {
        BOOST_CHECK_MESSAGE(!decoder.DecodeReady(), check_msg.str());
    }
}

BOOST_AUTO_TEST_CASE(fec_test_providechunk_cm256)
{
    for (const auto memory_usage_mode : memory_usage_modes) {
        // default extra encoded chunk, no drops
        providechunk_test(memory_usage_mode, 2, true);

        // 2 extra encoded chunks, 2 dropped chunks
        providechunk_test(memory_usage_mode, 2, true, 2, 2);

        // 2 extra encoded chunks, 1 dropped chunk
        providechunk_test(memory_usage_mode, 2, true, 2, 1);

        // 2 extra encoded chunks, 3 dropped chunks
        providechunk_test(memory_usage_mode, 2, false, 2, 3);

        // default extra encoded chunk, no drops
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS, true);

        // 10 extra encoded chunks, 10 dropped chunks
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS, true, 10, 10);

        // 10 extra encoded chunks, 7 dropped chunks
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS, true, 10, 7);

        // 10 extra encoded chunks, 12 dropped chunks
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS, false, 10, 12);
    }
}

BOOST_AUTO_TEST_CASE(fec_test_providechunk_wirehair)
{
    for (const auto memory_usage_mode : memory_usage_modes) {
        // default extra encoded chunk, no drops
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS + 10, true, default_encoding_overhead);

        // 10 extra encoded chunks, 5 dropped chunks
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS + 10, true, 10, 5);

        // 10 extra encoded chunks, 7 dropped chunks
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS + 10, true, 10, 7);

        // 10 extra encoded chunks, 12 dropped chunks
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS + 10, false, 10, 12);

        // 10 extra encoded chunks, 15 dropped chunks
        providechunk_test(memory_usage_mode, CM256_MAX_CHUNKS + 10, false, 10, 15);
    }
}


void test_providechunk_repetition(MemoryUsageMode memory_usage_mode)
{
    constexpr size_t n_encoded_chunks = 3;
    constexpr size_t block_size = 10;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
                         std::forward_as_tuple(new FECChunkType[n_encoded_chunks]),
                         std::forward_as_tuple(n_encoded_chunks));

    std::vector<unsigned char> original_data(block_size);
    fill_with_random_data(original_data);

    FECEncoder block_encoder(&original_data, &block_fec_chunks);

    for (size_t vector_idx = 0; vector_idx < n_encoded_chunks; vector_idx++) {
        block_encoder.BuildChunk(vector_idx);
    }

    // With repetition coding, receiving a single chunk should be enough.
    // There were 3 encoded chunks, but let's assume 2 of them were dropped
    // and the receiver only received the 3rd encoded chunk.

    FECDecoder decoder(block_size, memory_usage_mode);
    decoder.ProvideChunk(&block_fec_chunks.first[2], 2);

    BOOST_CHECK_MESSAGE(decoder.DecodeReady(), memory_usage_mode);
    check_chunk_equal(&block_fec_chunks.first[2], original_data);
}

BOOST_AUTO_TEST_CASE(fec_test_providechunk_repetition)
{
    for (const auto memory_usage_mode : memory_usage_modes) {
        test_providechunk_repetition(memory_usage_mode);
    }
}

BOOST_AUTO_TEST_CASE(fec_test_creation_removal_chunk_file)
{
    fs::path filename;
    {
        // FECDecoder's constructor should create the file in the partial_blocks directory
        FECDecoder decoder(10000, MemoryUsageMode::USE_MMAP);
        filename = decoder.GetFileName();
        BOOST_CHECK(fs::exists(filename));
    } // When FECDecoder's destructor is called, it should remove the file

    BOOST_CHECK(!fs::exists(filename));

    {
        // Now construct the FECDecoder object with keep_mmap_file=true
        FECDecoder decoder(10000, MemoryUsageMode::USE_MMAP, "" /* obj_id */, true /* keep_mmap_file */);
        filename = decoder.GetFileName();
        BOOST_CHECK(fs::exists(filename));
    } // When FECDecoder's destructor is called, it should NOT remove the file

    BOOST_CHECK(fs::exists(filename));
}

BOOST_AUTO_TEST_CASE(fec_test_chunk_file_stays_if_destructor_not_called)
{
    fs::path filename;
    {
        FECDecoder* decoder = new FECDecoder(10000, MemoryUsageMode::USE_MMAP);
        filename = decoder->GetFileName();
        BOOST_CHECK(fs::exists(filename));
    }
    BOOST_CHECK(fs::exists(filename));
}

BOOST_AUTO_TEST_CASE(fec_test_filename_is_empty_in_memory_mode)
{
    fs::path filename;

    // FECDecoder's constructor shouldn't intialize filename
    FECDecoder decoder(10000, MemoryUsageMode::USE_MEMORY);
    filename = decoder.GetFileName();
    BOOST_CHECK(filename.empty());
}

BOOST_AUTO_TEST_CASE(fec_test_decoding_multiple_blocks_in_parallel)
{
    size_t n_decoders = 1000;
    size_t n_uncoded_chunks = CM256_MAX_CHUNKS + 1;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks;
    size_t n_chunks_per_block = n_uncoded_chunks + default_encoding_overhead;

    std::vector<TestData> test_data_vec;

    // FECDecoder is neither copyable nor movable, create a vector of unique_ptr instead
    std::vector<std::unique_ptr<FECDecoder>> decoders_vec;

    for (size_t i = 0; i < n_decoders; i++) {
        TestData test_data;
        generate_encoded_chunks(data_size, test_data, default_encoding_overhead);
        test_data_vec.emplace_back(std::move(test_data));

        // randomly instantiate some decoders in mmap mode and some in memory mode
        if (rand() % 2) {
            decoders_vec.emplace_back(std::move(std::make_unique<FECDecoder>(data_size, MemoryUsageMode::USE_MMAP)));
        } else {
            decoders_vec.emplace_back(std::move(std::make_unique<FECDecoder>(data_size, MemoryUsageMode::USE_MEMORY)));
        }
    }

    // Provide one chunk to each decoder in a round robin fashion
    for (size_t i = 0; i < n_chunks_per_block; i++) {
        for (size_t j = 0; j < n_decoders; j++) {
            decoders_vec[j]->ProvideChunk(test_data_vec[j].encoded_chunks[i].data(), test_data_vec[j].chunk_ids[i]);
        }
    }

    bool all_decoded_successfully = true;
    for (size_t i = 0; i < n_decoders; i++) {
        BOOST_ASSERT(decoders_vec[i]->DecodeReady());
        std::vector<unsigned char> decoded_data = decoders_vec[i]->GetDecodedData();

        BOOST_ASSERT(decoded_data.size() == test_data_vec[i].original_data.size());

        // do not use BOOST_CHECK_EQUAL_COLLECTIONS for comparison here. It will generate
        // at least n_decoders lines of useless log message in case of successful run
        if (!std::equal(decoded_data.begin(), decoded_data.end(), test_data_vec[i].original_data.begin())) {
            all_decoded_successfully = false;
            break;
        }
    }
    BOOST_CHECK(all_decoded_successfully);
}

BOOST_AUTO_TEST_CASE(fec_test_map_storage_initialized_correctly)
{
    TestData test_data;
    size_t n_chunks = 5;
    size_t data_size = FEC_CHUNK_SIZE * n_chunks;
    generate_encoded_chunks(data_size, test_data);
    std::string obj_id = random_string();
    FECDecoder decoder_a(data_size, MemoryUsageMode::USE_MMAP, obj_id);
    FecMmapStorage map_storage_a(decoder_a.GetFileName(), decoder_a.GetChunkCount());

    bool initialized_fine = true;
    for (size_t i = 0; i < n_chunks; i++) {
        if (!CHUNK_ID_IS_NOT_SET(map_storage_a.GetChunkId(i)) || *map_storage_a.GetChunk(i) != '\0') {
            initialized_fine = false;
            break;
        }
    }
    BOOST_CHECK(initialized_fine);

    for (size_t i = 0; i < n_chunks - 1; i++) {
        decoder_a.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }

    // A new decoder with the same filename (for example, a decoder created in
    // recovery mode)
    FECDecoder decoder_b(data_size, MemoryUsageMode::USE_MMAP, obj_id);
    BOOST_CHECK_EQUAL(decoder_a.GetFileName(), decoder_b.GetFileName());
    BOOST_CHECK_EQUAL(decoder_a.GetChunkCount(), decoder_b.GetChunkCount());

    // The expectation is that the new decoder does not reset the values (chunk
    // data and id) that are already stored in the file
    FecMmapStorage map_storage_b(decoder_b.GetFileName(), decoder_b.GetChunkCount());
    bool stored_items_untouched = true;
    for (size_t i = 0; i < n_chunks - 1; i++) {
        if (CHUNK_ID_IS_NOT_SET(map_storage_b.GetChunkId(i)) || *map_storage_b.GetChunk(i) == '\0') {
            stored_items_untouched = false;
            break;
        }
    }
    BOOST_CHECK(stored_items_untouched);
}

BOOST_AUTO_TEST_CASE(fec_test_map_storage_recoverable)
{
    TestData test_data;
    size_t n_chunks = 5;
    size_t data_size = FEC_CHUNK_SIZE * n_chunks;
    generate_encoded_chunks(data_size, test_data);
    std::string obj_id = random_string();
    FECDecoder decoder(data_size, MemoryUsageMode::USE_MMAP, obj_id);
    {
        FecMmapStorage map_storage(decoder.GetFileName(), decoder.GetChunkCount(), true);
        BOOST_CHECK(!map_storage.IsRecoverable());
    }

    decoder.ProvideChunk(test_data.encoded_chunks[0].data(), test_data.chunk_ids[0]);
    {
        FecMmapStorage map_storage(decoder.GetFileName(), decoder.GetChunkCount(), true);
        BOOST_CHECK(map_storage.IsRecoverable());
    }

    {
        FecMmapStorage map_storage(decoder.GetFileName(), decoder.GetChunkCount());
        // When FecMmapStorage is not instantiated with create=true, the IsRecoverable always returns false
        BOOST_CHECK(!map_storage.IsRecoverable());
    }
}

// checks if the chunk ids stored in the filename match the ids in the expected_chunk_ids vector
void check_stored_chunk_ids(const FECDecoder& decoder, const std::vector<uint32_t>& expected_chunk_ids)
{
    FecMmapStorage map_storage(decoder.GetFileName(), decoder.GetChunkCount());
    std::vector<uint32_t> stored_chunk_ids;

    for (size_t i = 0; i < decoder.GetChunksRcvd(); i++) {
        stored_chunk_ids.push_back(map_storage.GetChunkId(i));
    }

    // do not compare stored_chunk_ids with the whole expected_chunk_ids, as this function
    // can also run for partial blocks in which not all chunk_id slots are filled
    BOOST_CHECK_EQUAL_COLLECTIONS(expected_chunk_ids.begin(), expected_chunk_ids.begin() + stored_chunk_ids.size(),
                                  stored_chunk_ids.begin(), stored_chunk_ids.end());
}

BOOST_AUTO_TEST_CASE(fec_test_chunk_ids_in_mmap_storage_test)
{
    TestData test_data;
    size_t n_chunks = 21;
    size_t data_size = FEC_CHUNK_SIZE * n_chunks;
    generate_encoded_chunks(data_size, test_data);

    FECDecoder decoder(data_size, MemoryUsageMode::USE_MMAP);

    // provide 1/3 of the chunks and test
    for (size_t i = 0; i < n_chunks / 3; i++) {
        decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }
    check_stored_chunk_ids(decoder, test_data.chunk_ids);

    // provide next 1/3 of the chunks and test
    for (size_t i = n_chunks / 3; i < (2 * n_chunks / 3); i++) {
        decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }
    check_stored_chunk_ids(decoder, test_data.chunk_ids);

    // provide the rest of the chunks and test
    for (size_t i = (2 * n_chunks / 3); i < n_chunks; i++) {
        decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }
    check_stored_chunk_ids(decoder, test_data.chunk_ids);
}


BOOST_AUTO_TEST_CASE(fec_test_map_storage_insert)
{
    std::vector<unsigned char> test_data_a(FEC_CHUNK_SIZE);
    std::vector<unsigned char> test_data_b(FEC_CHUNK_SIZE / 2);
    std::vector<unsigned char> test_data_c(FEC_CHUNK_SIZE);

    fill_with_random_data(test_data_a);
    fill_with_random_data(test_data_b);
    // Set half of the test_data_b items to 0
    test_data_b.insert(test_data_b.end(), FEC_CHUNK_SIZE / 2, 0);
    fill_with_random_data(test_data_c);

    FECDecoder decoder(FEC_CHUNK_SIZE * 5, MemoryUsageMode::USE_MMAP);
    FecMmapStorage map_storage(decoder.GetFileName(), decoder.GetChunkCount());

    // Insert into consequtive indexes
    map_storage.Insert(test_data_a.data(), 1, 0);
    map_storage.Insert(test_data_b.data(), 12, 1);
    map_storage.Insert(test_data_c.data(), 123, 2);
    {
        check_chunk_equal(map_storage.GetChunk(0), test_data_a);
        check_chunk_equal(map_storage.GetChunk(1), test_data_b);
        check_chunk_equal(map_storage.GetChunk(2), test_data_c);

        BOOST_CHECK_EQUAL(1, map_storage.GetChunkId(0));
        BOOST_CHECK_EQUAL(12, map_storage.GetChunkId(1));
        BOOST_CHECK_EQUAL(123, map_storage.GetChunkId(2));
    }

    // Insert into non consequtive indexes
    map_storage.Insert(test_data_a.data(), 1, 0);
    map_storage.Insert(test_data_b.data(), 12, 2);
    map_storage.Insert(test_data_c.data(), 123, 4);
    {
        check_chunk_equal(map_storage.GetChunk(0), test_data_a);
        check_chunk_equal(map_storage.GetChunk(2), test_data_b);
        check_chunk_equal(map_storage.GetChunk(4), test_data_c);

        BOOST_CHECK_EQUAL(1, map_storage.GetChunkId(0));
        BOOST_CHECK_EQUAL(12, map_storage.GetChunkId(2));
        BOOST_CHECK_EQUAL(123, map_storage.GetChunkId(4));
    }

    // Rewrite into already written slots
    map_storage.Insert(test_data_a.data(), 1, 2);
    map_storage.Insert(test_data_b.data(), 12, 4);
    map_storage.Insert(test_data_c.data(), 123, 0);
    {
        check_chunk_equal(map_storage.GetChunk(2), test_data_a);
        check_chunk_equal(map_storage.GetChunk(4), test_data_b);
        check_chunk_equal(map_storage.GetChunk(0), test_data_c);

        BOOST_CHECK_EQUAL(1, map_storage.GetChunkId(2));
        BOOST_CHECK_EQUAL(12, map_storage.GetChunkId(4));
        BOOST_CHECK_EQUAL(123, map_storage.GetChunkId(0));
    }
}

void test_decoding_getdataptr(size_t n_uncoded_chunks, MemoryUsageMode memory_usage_mode)
{
    std::ostringstream check_msg;
    check_msg << "n_uncoded_chunks = " << n_uncoded_chunks << ", memory_usage_mode = " << memory_usage_mode;
    // Random test data that does not fill n_uncoded_chunks exactly (padded)
    TestData test_data;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks - (FEC_CHUNK_SIZE / 2);
    BOOST_CHECK_MESSAGE(generate_encoded_chunks(data_size, test_data, default_encoding_overhead), check_msg.str());
    size_t n_encoded_chunks = test_data.encoded_chunks.size();

    // Provide chunks into the FEC Decoder
    FECDecoder decoder(data_size, memory_usage_mode);
    for (size_t i = 0; i < n_encoded_chunks; i++) {
        decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }
    BOOST_CHECK_MESSAGE(decoder.DecodeReady(), check_msg.str());

    // Get the decoded data using GetDecodedData
    std::vector<unsigned char> decoded_data = decoder.GetDecodedData();

    // Get the decoded data using GetDataPtr
    // NOTE: there are two options when using GetDataPtr:
    //   1) Allocate data_size on the resulting std::vector<unsigned char> and
    //   memcpy the last chunk while considering the padding.
    //   2) Allocate enough space to copy full n_uncoded_chunks chunks. Then,
    //   consider only decoded_data2[0] to decoded_data2[data_size-1].
    // Use the second approach in the sequel.
    std::vector<unsigned char> decoded_data2(n_uncoded_chunks * FEC_CHUNK_SIZE);
    for (size_t i = 0; i < (size_t)n_uncoded_chunks; i++)
        memcpy(&decoded_data2[i * FEC_CHUNK_SIZE], decoder.GetDataPtr(i), FEC_CHUNK_SIZE);

    // Compare both to the original
    BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
                                  test_data.original_data.begin(), test_data.original_data.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data2.begin(), decoded_data2.begin() + data_size,
                                  test_data.original_data.begin(), test_data.original_data.end());
}

BOOST_AUTO_TEST_CASE(fec_test_decoding_getdataptr)
{
    std::vector<size_t> chunk_counts{1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 10};
    for (const auto chunk_count : chunk_counts) {
        for (const auto memory_usage_mode : memory_usage_modes) {
            test_decoding_getdataptr(chunk_count, memory_usage_mode);
        }
    }
}

BOOST_AUTO_TEST_CASE(fec_test_decoder_move_assignment_operator)
{
    {
        // - both decoders without obj_id
        // - decoder1 constructed in mmap mode (gets a filename)
        // - decoder2 default-constructed (without a filename)
        FECDecoder decoder1(5000, MemoryUsageMode::USE_MMAP);
        auto filename1 = decoder1.GetFileName();
        FECDecoder decoder2;
        decoder2 = std::move(decoder1);
        // Given that decoder2 did not have a filename originally, its filename
        // becomes filename1 after the move assignment.
        BOOST_CHECK_EQUAL(filename1, decoder2.GetFileName());
        BOOST_CHECK(fs::exists(decoder2.GetFileName()));
    }
    {
        // - decoder1 with obj_id, decoder2 without it
        // - decoder1 constructed in mmap mode (gets a filename)
        // - decoder2 default-constructed (without a filename)
        std::string obj_id = random_string();
        FECDecoder decoder1(5000, MemoryUsageMode::USE_MMAP, obj_id);
        auto filename1 = decoder1.GetFileName();
        FECDecoder decoder2;
        decoder2 = std::move(decoder1);
        // Again, because decoder2 was default-constructed, its filename becomes
        // that of the moved object (decoder1).
        BOOST_CHECK_EQUAL(filename1, decoder2.GetFileName());
        BOOST_CHECK(fs::exists(decoder2.GetFileName()));
    }
    {
        // - both decoders constructed in mmap mode with an obj_id
        FECDecoder decoder1(5000, MemoryUsageMode::USE_MMAP, "1234_body");
        auto filename1 = decoder1.GetFileName();
        FECDecoder decoder2(4000, MemoryUsageMode::USE_MMAP, "5678_body");
        auto filename2 = decoder2.GetFileName();
        decoder2 = std::move(decoder1);
        // In this case, decoder2 does have a filename originally. Thus, after
        // the move assignment, the file pointed by filename1 gets moved into
        // decoder2 and renamed as filename2. Meanwhile, the original filename2
        // is destroyed and only its name is preserved, although now with the
        // contents of filename1.
        BOOST_CHECK(!fs::exists(filename1));
        BOOST_CHECK(fs::exists(filename2));
        BOOST_CHECK_EQUAL(filename2, decoder2.GetFileName());
    }
    {
        // - decoder1 default-constructed
        // - decoder2 constructed in mmap mode with an obj_id
        FECDecoder decoder1;
        std::string obj_id = random_string();
        FECDecoder decoder2(5000, MemoryUsageMode::USE_MMAP, obj_id);
        auto filename2 = decoder2.GetFileName();
        decoder2 = std::move(decoder1);
        // In this case, decoder1 does not own a file. Hence, the move
        // assignment operator does not apply any file renaming. Ultimately,
        // decoder2's filename should be preserved after the move.
        BOOST_CHECK_EQUAL(filename2, decoder2.GetFileName());
    }
    {
        // - decoder1 constructed in memory mode
        // - decoder2 default-constructed (also in memory mode, the default)
        FECDecoder decoder1(5000, MemoryUsageMode::USE_MEMORY);
        FECDecoder decoder2;
        BOOST_CHECK_NO_THROW(decoder2 = std::move(decoder1));
        // no checks required, as there is no files. just make sure = operator
        // does not throw.
    }
}

void test_decode_using_moved_decoder(size_t n_uncoded_chunks, MemoryUsageMode memory_usage_mode)
{
    std::ostringstream check_msg;
    check_msg << "n_uncoded_chunks = " << n_uncoded_chunks << ", memory_usage_mode = " << memory_usage_mode;

    TestData test_data;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks;
    generate_encoded_chunks(data_size, test_data, default_encoding_overhead);

    size_t n_encoded_chunks = n_uncoded_chunks + default_encoding_overhead;

    // Move a newly instantiated FECDecoder
    {
        // default construct in memory mode
        FECDecoder decoder;
        // Move a non default constructed FECDecoder into decoder
        std::string obj_id = random_string();
        decoder = FECDecoder(data_size, memory_usage_mode, obj_id);
        for (size_t i = 0; i < n_encoded_chunks; i++) {
            decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
        }

        BOOST_CHECK_MESSAGE(decoder.DecodeReady(), check_msg.str());
        std::vector<unsigned char> decoded_data = decoder.GetDecodedData();
        BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
                                      test_data.original_data.begin(), test_data.original_data.end());
    }

    // Move a FECDecoder which already received some chunks
    {
        FECDecoder decoder1(data_size);
        for (size_t i = 0; i < n_encoded_chunks / 2; i++) {
            decoder1.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
        }

        FECDecoder decoder2;
        decoder2 = std::move(decoder1);
        for (size_t i = n_encoded_chunks / 2; i < n_encoded_chunks; i++) {
            decoder2.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
        }

        BOOST_CHECK_MESSAGE(decoder2.DecodeReady(), check_msg.str());
        std::vector<unsigned char> decoded_data = decoder2.GetDecodedData();
        BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
                                      test_data.original_data.begin(), test_data.original_data.end());
    }
}

BOOST_AUTO_TEST_CASE(fec_test_decode_using_moved_decoder)
{
    std::vector<size_t> chunk_counts{1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 10};
    for (const auto chunk_count : chunk_counts) {
        for (const auto memory_usage_mode : memory_usage_modes) {
            test_decode_using_moved_decoder(chunk_count, memory_usage_mode);
        }
    }
}

/**
 * Test helper funtion for testing recovery of FECDecoder
 * @param[in] n_uncoded_chunks     number of uncoded chunk to be generated
 * @param[in] n_overhead_chunks    number of overhead chunks to be generated
 * @param[in] abort_at             floating point indicating the percentage at which the first decoder should be aborted
 * @param[in] start_second_at      floating point indicating the percentage from which the second decoder should start receving chunks
 * @param[in] expected_result      whether the test is expected to pass successfully or not
 *
 */
void recovery_test(size_t n_uncoded_chunks, size_t n_overhead_chunks, size_t abort_at, size_t start_second_at, bool expected_result)
{
    size_t n_encoded_chunks = n_uncoded_chunks + n_overhead_chunks;
    assert(abort_at <= n_encoded_chunks);
    assert(start_second_at <= n_encoded_chunks);

    BOOST_TEST_MESSAGE("Two-step recovery test - Uncoded chunks: " << n_uncoded_chunks << " - Overhead: " << n_overhead_chunks << " - First batch: [0, " << abort_at << ") - Second: [" << start_second_at << ", " << n_encoded_chunks << ")");

    TestData test_data;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks;
    generate_encoded_chunks(data_size, test_data, n_overhead_chunks);

    std::string obj_id = random_string();

    FECDecoder first_decoder(data_size, MemoryUsageMode::USE_MMAP, obj_id);

    for (size_t i = 0; i < abort_at; i++) {
        first_decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }

    /// Assume the application was aborted here *******
    /// The file is left on the disk but the decoding is not finished yet

    // try to recover the data on disk first, and continue decoding with second_decoder
    FECDecoder second_decoder(data_size, MemoryUsageMode::USE_MMAP, obj_id);

    for (size_t i = start_second_at; i < n_encoded_chunks; i++) {
        second_decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }

    if (expected_result) {
        BOOST_CHECK(second_decoder.DecodeReady());
        std::vector<unsigned char> decoded_data = second_decoder.GetDecodedData();
        BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
                                      test_data.original_data.begin(), test_data.original_data.end());
    } else {
        BOOST_CHECK(!second_decoder.DecodeReady());
    }
}

BOOST_AUTO_TEST_CASE(fec_test_fecdecoder_recovery_in_two_steps)
{
    // cm256
    recovery_test(2, 0, 1, 1, true);   // decode half of the chunks in each step
    recovery_test(2, 0, 1, 0, true);   // decode all over again in the second step
    recovery_test(10, 0, 5, 5, true);  // decode half of the chunks in each step
    recovery_test(10, 0, 3, 3, true);  // decode 30% first, then the other 70%
    recovery_test(10, 0, 3, 4, false); // miss 1 chunk (> overhead) and fail decoding
    recovery_test(10, 0, 9, 0, true);  // decode all over again in the second step
    recovery_test(6, 4, 5, 5, true);   // decode half of the chunks in each step
    recovery_test(6, 4, 4, 0, true);   // decode all over again in the second step
    recovery_test(6, 4, 3, 3, true);   // decode 30% first, then the other 70%
    recovery_test(6, 4, 4, 6, true);   // miss 2 chunks (< overhead) and decode successfully
    recovery_test(6, 4, 4, 9, false);  // miss 5 chunks (> overhead) and fail decoding
    recovery_test(6, 4, 6, 0, true);   // abort and continue after having enough chunks
    recovery_test(6, 4, 8, 0, true);   // receive most of the chunks twice
    recovery_test(6, 4, 10, 0, true);  // receive all chunks twice

    // wirehair
    recovery_test(90, 10, 70, 0, true);   // decode all over again in the second step
    recovery_test(90, 10, 50, 50, true);  // decode half of the chunks in each step
    recovery_test(90, 10, 40, 45, true);  // miss 5 chunks (< overhead) and decode successfully
    recovery_test(90, 10, 40, 60, false); // miss 20 chunks (> overhead) and fail decoding
    recovery_test(90, 10, 80, 0, true);   // receive most of the chunks twice
    recovery_test(90, 10, 100, 0, true);  // receive all chunks twice
    recovery_test(90, 10, 90, 0, true);   // abort and continue after having enough chunks
}

void test_fecdecoder_recovery_after_decoding(size_t n_uncoded_chunks)
{
    // This test case tests the situation in which the mmap-mode decoder has all
    // the chunks and proceeds with the decoding, but for some reason the
    // application exits before the decoded data is used and, more importantly,
    // before the corresponding mmaped file is removed from disk. For example,
    // this scenario can arise in udprelay.cpp when the header object is
    // decodable but the application closes before the associated body object
    // becomes decodable. In this case, the header mmap file would remain in
    // disk because udprelay.cpp only removes the header file when the body
    // object also becomes decodable.
    //
    // As a result, on the next run, there will be another attempt to decode the
    // same chunks from the recovered mmap file. In this case, the fact that the
    // previous session already decoded the data once should not prevent the
    // recoverability of the chunks on the subsequent session.

    TestData test_data;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks;
    generate_encoded_chunks(data_size, test_data, default_encoding_overhead);
    size_t n_encoded_chunks = n_uncoded_chunks + default_encoding_overhead;

    std::string obj_id = random_string();

    // First session
    {
        FECDecoder decoder(data_size, MemoryUsageMode::USE_MMAP, obj_id, true /* keep_mmap_file */);

        for (size_t i = 0; i < n_encoded_chunks; i++) {
            decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
        }

        // calling GetDecodedData will make sure decoding happens
        decoder.GetDecodedData();
    }

    /// Assume the application was aborted here *******

    // Second session
    {
        FECDecoder decoder(data_size, MemoryUsageMode::USE_MMAP, obj_id);
        BOOST_CHECK_MESSAGE(decoder.DecodeReady(), n_uncoded_chunks);
        std::vector<unsigned char> decoded_data = decoder.GetDecodedData();
        BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
                                      test_data.original_data.begin(), test_data.original_data.end());
    }
}

BOOST_AUTO_TEST_CASE(fec_test_fecdecoder_recovery_after_decoding)
{
    std::vector<size_t> chunk_counts{2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 10};
    for (const auto chunk_count : chunk_counts) {
        test_fecdecoder_recovery_after_decoding(chunk_count);
    }
}

void test_fecdecoder_recovery_with_N_decoders(size_t n_uncoded_chunks)
{
    // This test will cover the worst-case scenario for recovering chunks
    // If the decoder is going to receive N chunks, it will receive them via N different decoders.
    // As if the decoder was restarted after receiving every chunk.
    // Expectation is that the last decoder is still able to decode successfully.

    TestData test_data;
    size_t n_overhead_chunks = default_encoding_overhead;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks;
    size_t n_encoded_chunks = n_uncoded_chunks + n_overhead_chunks;

    generate_encoded_chunks(data_size, test_data, n_overhead_chunks);

    std::string obj_id = random_string();

    std::vector<std::unique_ptr<FECDecoder>> decoders_vec;
    for (size_t i = 0; i < n_encoded_chunks - 1; i++) {
        decoders_vec.emplace_back(std::move(std::make_unique<FECDecoder>(data_size, MemoryUsageMode::USE_MMAP, obj_id)));
        decoders_vec.back()->ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }

    FECDecoder final_decoder(data_size, MemoryUsageMode::USE_MMAP, obj_id);
    final_decoder.ProvideChunk(test_data.encoded_chunks[n_encoded_chunks - 1].data(), test_data.chunk_ids[n_encoded_chunks - 1]);

    BOOST_CHECK_MESSAGE(final_decoder.DecodeReady(), n_uncoded_chunks);
    std::vector<unsigned char> decoded_data = final_decoder.GetDecodedData();
    BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
                                  test_data.original_data.begin(), test_data.original_data.end());
}

BOOST_AUTO_TEST_CASE(fec_test_fecdecoder_recovery_with_N_decoders)
{
    std::vector<size_t> chunk_counts{1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 10};
    for (const auto chunk_count : chunk_counts) {
        test_fecdecoder_recovery_with_N_decoders(chunk_count);
    }
}


BOOST_AUTO_TEST_SUITE_END()
