
#include <boost/test/unit_test.hpp>
#include <fec.h>
#include <memory>
#include <test/setup_common.h>
#include <util/memory.h>
#include <util/system.h>

#define DIV_CEIL(a, b) (((a) + (b)-1) / (b))

constexpr char hex_digits[] = "0123456789ABCDEF";
constexpr size_t default_encoding_overhead = 3;

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
    auto rand_hex_gen = []() {
        auto h1 = hex_digits[(rand() % 16)];
        return h1;
    };
    std::generate(vec.begin(), vec.end(), rand_hex_gen);
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
        // build the chunk and make sure chunk_id is set correctly afterwards
        if (!block_encoder.BuildChunk(vector_idx) || block_fec_chunks.second[vector_idx] == 0) {
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

BOOST_FIXTURE_TEST_SUITE(fec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fec_buildchunk_invalid_idx_test)
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

BOOST_AUTO_TEST_CASE(fec_buildchunk_overwrite_wirehair)
{
    test_buildchunk_overwrite(CM256_MAX_CHUNKS + 1);
}


BOOST_AUTO_TEST_CASE(fec_buildchunk_overwrite_cm256)
{
    test_buildchunk_overwrite(CM256_MAX_CHUNKS - 1);
}


BOOST_AUTO_TEST_CASE(fec_buildchunk_repetition_coding)
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

BOOST_AUTO_TEST_CASE(fec_buildchunk_successful_Wirehair_encoder)
{
    // Choose block size bigger than CM256_MAX_CHUNKS to
    // force using wirehair encoder
    constexpr size_t n_uncoded_chunks = CM256_MAX_CHUNKS + 1;
    constexpr size_t block_size = n_uncoded_chunks * FEC_CHUNK_SIZE;
    TestData test_data;
    BOOST_CHECK(generate_encoded_chunks(block_size, test_data, default_encoding_overhead));
}

BOOST_AUTO_TEST_CASE(fec_buildchunk_successful_cm256_encoder)
{
    // Choose block size bigger than 1 chunk and smaller than
    // CM256_MAX_CHUNKS to force using cm256 encoder
    size_t block_size = FEC_CHUNK_SIZE + 1;
    TestData test_data;
    BOOST_CHECK(generate_encoded_chunks(block_size, test_data));
}

BOOST_AUTO_TEST_CASE(fec_providechunk_invalid_chunk_id_test)
{
    // Set data size in a way that CHUNK_COUNT_USES_CM256 is true
    constexpr size_t chunk_count = 2;
    constexpr size_t data_size = chunk_count * FEC_CHUNK_SIZE;
    std::vector<unsigned char> chunk(data_size);
    fill_with_random_data(chunk);

    FECDecoder decoder(data_size);
    BOOST_CHECK(!decoder.ProvideChunk(chunk.data(), 256));

    // Set data size in a way that CHUNK_COUNT_USES_CM256 is false
    constexpr size_t chunk_count2 = CM256_MAX_CHUNKS + 1;
    constexpr size_t data_size2 = chunk_count2 * FEC_CHUNK_SIZE;
    std::vector<unsigned char> chunk2(data_size2);
    fill_with_random_data(chunk2);

    FECDecoder decoder2(data_size2);
    BOOST_CHECK(!decoder2.ProvideChunk(chunk2.data(), FEC_CHUNK_COUNT_MAX + 1));
    BOOST_CHECK(!decoder.DecodeReady());
}

BOOST_AUTO_TEST_CASE(fec_providechunk_small_chunk_count)
{
    // Generate random data fitting within a single chunk
    size_t data_size = 5;
    FECDecoder decoder(data_size);
    std::vector<unsigned char> original_data(data_size);
    fill_with_random_data(original_data);

    // Corresponding zero-padded chunk
    std::vector<unsigned char> padded_chunk(original_data);
    padded_chunk.resize(FEC_CHUNK_SIZE, 0); // zero-padding

    // After providing the single chunk of data to the FEC decoder, the latter
    // should be ready to decode the message
    BOOST_CHECK(decoder.ProvideChunk(padded_chunk.data(), 0));
    BOOST_CHECK(decoder.HasChunk(0));
    BOOST_CHECK(decoder.DecodeReady());

    // The original message should be entirely on the single chunk under test
    check_chunk_equal(decoder.GetDataPtr(0), original_data);
}


void providechunk_test(size_t n_uncoded_chunks, bool expected_result, size_t n_overhead_chunks = 0, size_t n_dropped_chunks = 0)
{
    TestData test_data;
    size_t data_size = FEC_CHUNK_SIZE * n_uncoded_chunks;
    generate_encoded_chunks(data_size, test_data, n_overhead_chunks);

    size_t n_encoded_chunks = n_uncoded_chunks + n_overhead_chunks;

    // Randomly pick some indexes to be dropped
    // Make sure exactly n_dropped_chunks unique indexes are selected
    std::unordered_set<size_t> dropped_indexes;
    while (dropped_indexes.size() < n_dropped_chunks)
        dropped_indexes.insert(rand() % n_encoded_chunks);

    FECDecoder decoder(data_size);
    for (size_t i = 0; i < n_encoded_chunks; i++) {
        if (dropped_indexes.find(i) != dropped_indexes.end()) {
            // chunk i has been dropped
            continue;
        }
        decoder.ProvideChunk(test_data.encoded_chunks[i].data(), test_data.chunk_ids[i]);
    }

    if (expected_result) {
        BOOST_CHECK(decoder.DecodeReady());
        std::vector<unsigned char> decoded_data(data_size);
        for (size_t i = 0; i < n_uncoded_chunks; i++)
            memcpy(&decoded_data[i * FEC_CHUNK_SIZE], decoder.GetDataPtr(i), FEC_CHUNK_SIZE);

        BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_data.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
            test_data.original_data.begin(), test_data.original_data.end());
    } else {
        BOOST_CHECK(!decoder.DecodeReady());
    }
}

BOOST_AUTO_TEST_CASE(fec_providechunk_cm256)
{
    // default extra encoded chunk, no drops
    providechunk_test(2, true);

    // 2 extra encoded chunks, 2 dropped chunks
    providechunk_test(2, true, 2, 2);

    // 2 extra encoded chunks, 1 dropped chunk
    providechunk_test(2, true, 2, 1);

    // 2 extra encoded chunks, 3 dropped chunks
    providechunk_test(2, false, 2, 3);

    // default extra encoded chunk, no drops
    providechunk_test(CM256_MAX_CHUNKS, true);

    // 10 extra encoded chunks, 10 dropped chunks
    providechunk_test(CM256_MAX_CHUNKS, true, 10, 10);

    // 10 extra encoded chunks, 7 dropped chunks
    providechunk_test(CM256_MAX_CHUNKS, true, 10, 7);

    // 10 extra encoded chunks, 12 dropped chunks
    providechunk_test(CM256_MAX_CHUNKS, false, 10, 12);
}

BOOST_AUTO_TEST_CASE(fec_providechunk_wirehair)
{
    // default extra encoded chunk, no drops
    providechunk_test(CM256_MAX_CHUNKS + 10, true, default_encoding_overhead);

    // 10 extra encoded chunks, 5 dropped chunks
    providechunk_test(CM256_MAX_CHUNKS + 10, true, 10, 5);

    // 10 extra encoded chunks, 7 dropped chunks
    providechunk_test(CM256_MAX_CHUNKS + 10, true, 10, 7);

    // 10 extra encoded chunks, 12 dropped chunks
    providechunk_test(CM256_MAX_CHUNKS + 10, false, 10, 12);

    // 10 extra encoded chunks, 15 dropped chunks
    providechunk_test(CM256_MAX_CHUNKS + 10, false, 10, 15);
}

BOOST_AUTO_TEST_CASE(fec_providechunk_repetition)
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

    FECDecoder decoder(block_size);
    decoder.ProvideChunk(&block_fec_chunks.first[2], 2);

    BOOST_CHECK(decoder.DecodeReady());
    check_chunk_equal(&block_fec_chunks.first[2], original_data);
}

BOOST_AUTO_TEST_CASE(test_creation_removal_chunk_file)
{
    fs::path filename;
    {
        // FECDecoder's constructor should create the file in the partial_blocks directory
        FECDecoder decoder(10000);
        filename = decoder.GetFileName();
        BOOST_CHECK(fs::exists(filename));
    } // When FECDecoder's destructor is called, it should remove the file

    BOOST_CHECK(!fs::exists(filename));
}


BOOST_AUTO_TEST_CASE(test_chunk_file_stays_if_destructor_not_called)
{
    fs::path filename;
    {
        FECDecoder* decoder = new FECDecoder(10000);
        filename = decoder->GetFileName();
        BOOST_CHECK(fs::exists(filename));
    }
    BOOST_CHECK(fs::exists(filename));

    // cleanup the system!
    fs::remove(filename);
}

BOOST_AUTO_TEST_CASE(test_decoding_multiple_blocks_in_parallel)
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
        decoders_vec.emplace_back(std::move(MakeUnique<FECDecoder>(data_size)));
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
        std::vector<unsigned char> decoded_data(data_size);
        for (size_t j = 0; j < n_uncoded_chunks; j++)
            memcpy(&decoded_data[j * FEC_CHUNK_SIZE], decoders_vec[i]->GetDataPtr(j), FEC_CHUNK_SIZE);

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

BOOST_AUTO_TEST_SUITE_END()
