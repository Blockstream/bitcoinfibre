#include <boost/mpl/list.hpp>
#include <boost/test/unit_test.hpp>
#include <fs.h>
#include <mmapstorage.h>
#include <test/util/setup_common.h>
#include <util/system.h>

typedef boost::mpl::list<char, uint8_t, uint32_t> storage_data_types;


struct MmapStorageTestingSetup : public BasicTestingSetup {
    /**
     * The files generated within the partial_blocks directory during tests get
     * cleaned once the tests finish, but the directories stay. Thus, after a
     * while, "/tmp/test_common_Bitcoin Core" will be filled with useless empty
     * directories. The FecTestingSetup destructor runs after all the tests and
     * removes these directories.
     */
    ~MmapStorageTestingSetup()
    {
        fs::path partial_blocks = gArgs.GetDataDirNet() / "temp_files";
        fs::remove_all(partial_blocks.parent_path());
    }
};


static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

static std::vector<unsigned char> generate_random_string(size_t len)
{
    std::vector<unsigned char> random_str;
    random_str.reserve(len);

    for (size_t i = 0; i < len; ++i) {
        random_str.push_back(alphanum[rand() % (sizeof(alphanum) - 1)]);
    }
    return random_str;
}

static fs::path get_random_temp_file()
{
    auto temp_name = generate_random_string(10);
    return gArgs.GetDataDirNet() / "temp_files" / reinterpret_cast<char*>(temp_name.data());
}

static void check_chunk_equal(const void* p_chunk1, std::vector<unsigned char>& chunk2, size_t chunk_data_size)
{
    // Chunk1 is the chunk under test, whose size is always chunk_data_size
    std::vector<unsigned char> chunk1(chunk_data_size);
    memcpy(chunk1.data(), p_chunk1, chunk_data_size);

    // Chunk2 represents the reference data that should be contained on
    // chunk1. Nevertheless, this data vector can occupy less than
    // chunk_data_size.
    const size_t size = chunk2.size();
    BOOST_CHECK(size <= chunk_data_size);

    // Compare the useful part of chunk1 (excluding zero-padding) against chunk2
    BOOST_CHECK_EQUAL_COLLECTIONS(chunk1.begin(), chunk1.begin() + size,
                                  chunk2.begin(), chunk2.end());

    // When chunk2's size is less than chunk_data_size, the chunk under test
    // (chunk1) should be zero-padded. Check:
    if (size < chunk_data_size) {
        const size_t n_padding = chunk_data_size - size;
        std::vector<unsigned char> padding(n_padding, 0);
        BOOST_CHECK_EQUAL_COLLECTIONS(chunk1.begin() + size, chunk1.end(),
                                      padding.begin(), padding.end());
    }
}

BOOST_FIXTURE_TEST_SUITE(mmapstorage_tests, MmapStorageTestingSetup)

BOOST_AUTO_TEST_CASE_TEMPLATE(map_storage_initialized_correctly, T, storage_data_types)
{
    size_t n_chunks = 5;
    auto filename = get_random_temp_file();
    size_t chunk_data_size = 1000;
    T meta_init_val = 127;

    MmapStorage<T> map_storage_a(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
    BOOST_CHECK(map_storage_a.Size() == ((chunk_data_size + sizeof(T)) * n_chunks));
    BOOST_CHECK(map_storage_a.GetStorage() != nullptr);

    bool initialized_fine = true;
    for (size_t i = 0; i < n_chunks; i++) {
        if (map_storage_a.GetChunkMeta(i) != meta_init_val || *map_storage_a.GetChunk(i) != '\0') {
            initialized_fine = false;
            break;
        }
    }
    BOOST_CHECK(initialized_fine);

    for (size_t i = 0; i < n_chunks; i++) {
        auto random_data = generate_random_string(chunk_data_size);
        map_storage_a.Insert(random_data.data(), i, i);
    }

    // The expectation is that the new mmapstorage does not reset the values
    // (data and metadata) that are already stored in the file for
    // create=true/false
    for (bool create : {false, true}) {
        MmapStorage<T> map_storage_b(filename, create, chunk_data_size, n_chunks, meta_init_val);
        BOOST_CHECK(map_storage_b.Size() == ((chunk_data_size + sizeof(T)) * n_chunks));
        BOOST_CHECK(map_storage_b.GetStorage() != nullptr);

        bool stored_items_untouched = true;
        for (size_t i = 0; i < n_chunks; i++) {
            if (map_storage_b.GetChunkMeta(i) == meta_init_val || *map_storage_b.GetChunk(i) == '\0') {
                stored_items_untouched = false;
                break;
            }
        }
        BOOST_CHECK(stored_items_untouched);
    }
}


BOOST_AUTO_TEST_CASE_TEMPLATE(map_storage_remove, T, storage_data_types)
{
    size_t n_chunks = 5;
    auto filename = get_random_temp_file();
    size_t chunk_data_size = 1000;
    T meta_init_val = 127;

    {
        MmapStorage<T> map_storage(filename, true, chunk_data_size, n_chunks, meta_init_val);
        BOOST_CHECK(fs::exists(filename));
        map_storage.Remove();
        BOOST_CHECK(!fs::exists(filename));
    }
}

BOOST_AUTO_TEST_CASE_TEMPLATE(map_storage_recoverable, T, storage_data_types)
{
    size_t n_chunks = 5;
    auto filename = get_random_temp_file();
    size_t chunk_data_size = 1000;
    T meta_init_val = 127;

    { // Insert no data
        MmapStorage<T> map_storage(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
        BOOST_CHECK(!map_storage.IsRecoverable());
        map_storage.Remove();
    }

    { // Insert data at the beginning
        MmapStorage<T> map_storage_a(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
        auto random_data = generate_random_string(chunk_data_size);
        map_storage_a.Insert(random_data.data(), 0, 0);

        MmapStorage<T> map_storage_b(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
        BOOST_CHECK(map_storage_b.IsRecoverable());
        map_storage_a.Remove();
    }

    {
        // Insert data at the end
        MmapStorage<T> map_storage_a(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
        auto random_data = generate_random_string(chunk_data_size);
        map_storage_a.Insert(random_data.data(), 0, n_chunks - 1);

        // Create another mmapstorage on the same file (which has data in)
        MmapStorage<T> map_storage_b(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
        BOOST_CHECK(map_storage_b.IsRecoverable());

        // When MmapStorage is instantiated with create=false, the IsRecoverable always returns false
        MmapStorage<T> map_storage_create_false(filename, false /* create */, chunk_data_size, n_chunks, meta_init_val);
        BOOST_CHECK(!map_storage_create_false.IsRecoverable());
    }
}

BOOST_AUTO_TEST_CASE_TEMPLATE(map_storage_insert, T, storage_data_types)
{
    size_t n_chunks = 5;
    auto filename = get_random_temp_file();
    size_t chunk_data_size = 1000;
    T meta_init_val = 127;

    std::vector<unsigned char> test_data_a = generate_random_string(chunk_data_size);
    std::vector<unsigned char> test_data_b = generate_random_string(chunk_data_size / 2);
    std::vector<unsigned char> test_data_c = generate_random_string(chunk_data_size);

    MmapStorage<T> map_storage(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);

    // Insert into consequtive indexes
    map_storage.Insert(test_data_a.data(), 1, 0);
    map_storage.Insert(test_data_b.data(), 12, 1);
    map_storage.Insert(test_data_c.data(), 123, 2);
    {
        check_chunk_equal(map_storage.GetChunk(0), test_data_a, chunk_data_size);
        check_chunk_equal(map_storage.GetChunk(1), test_data_b, chunk_data_size / 2);
        check_chunk_equal(map_storage.GetChunk(2), test_data_c, chunk_data_size);

        BOOST_CHECK_EQUAL(1, map_storage.GetChunkMeta(0));
        BOOST_CHECK_EQUAL(12, map_storage.GetChunkMeta(1));
        BOOST_CHECK_EQUAL(123, map_storage.GetChunkMeta(2));
    }

    // Insert into non consequtive indexes
    map_storage.Insert(test_data_a.data(), 1, 0);
    map_storage.Insert(test_data_b.data(), 12, 2);
    map_storage.Insert(test_data_c.data(), 123, 4);
    {
        check_chunk_equal(map_storage.GetChunk(0), test_data_a, chunk_data_size);
        check_chunk_equal(map_storage.GetChunk(2), test_data_b, chunk_data_size / 2);
        check_chunk_equal(map_storage.GetChunk(4), test_data_c, chunk_data_size);

        BOOST_CHECK_EQUAL(1, map_storage.GetChunkMeta(0));
        BOOST_CHECK_EQUAL(12, map_storage.GetChunkMeta(2));
        BOOST_CHECK_EQUAL(123, map_storage.GetChunkMeta(4));
    }

    // Rewrite into already written slots
    map_storage.Insert(test_data_a.data(), 1, 2);
    map_storage.Insert(test_data_b.data(), 12, 4);
    map_storage.Insert(test_data_c.data(), 123, 0);
    {
        check_chunk_equal(map_storage.GetChunk(2), test_data_a, chunk_data_size);
        check_chunk_equal(map_storage.GetChunk(4), test_data_b, chunk_data_size / 2);
        check_chunk_equal(map_storage.GetChunk(0), test_data_c, chunk_data_size);

        BOOST_CHECK_EQUAL(1, map_storage.GetChunkMeta(2));
        BOOST_CHECK_EQUAL(12, map_storage.GetChunkMeta(4));
        BOOST_CHECK_EQUAL(123, map_storage.GetChunkMeta(0));
    }
}

BOOST_AUTO_TEST_CASE_TEMPLATE(map_storage_update, T, storage_data_types)
{
    size_t n_chunks = 5;
    auto filename = get_random_temp_file();
    size_t chunk_data_size = 1000;
    T meta_init_val = 127;

    std::vector<unsigned char> test_data_a = generate_random_string(chunk_data_size);
    std::vector<unsigned char> test_data_b = generate_random_string(chunk_data_size);
    std::vector<unsigned char> test_data_c = generate_random_string(chunk_data_size);

    MmapStorage<T> map_storage(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);

    // Insert into consequtive indexes
    map_storage.Insert(test_data_a.data(), 1, 0);
    map_storage.Insert(test_data_b.data(), 12, 1);
    map_storage.Insert(test_data_c.data(), 123, 2);

    BOOST_CHECK(map_storage.GetChunkMeta(0) == 1);
    BOOST_CHECK(map_storage.GetChunkMeta(1) == 12);
    BOOST_CHECK(map_storage.GetChunkMeta(2) == 123);
}


BOOST_AUTO_TEST_CASE_TEMPLATE(map_storage_index_validation, T, storage_data_types)
{
    size_t n_chunks = 5;
    auto filename = get_random_temp_file();
    size_t chunk_data_size = 1000;
    T meta_init_val = 127;

    std::vector<unsigned char> test_data = generate_random_string(chunk_data_size);

    MmapStorage<T> map_storage(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
    map_storage.Insert(test_data.data(), 1, 0);

    BOOST_CHECK_THROW(map_storage.GetChunk(n_chunks), std::runtime_error);
    BOOST_CHECK_THROW(map_storage.GetChunkMeta(n_chunks), std::runtime_error);
    BOOST_CHECK_THROW(map_storage.Insert(test_data.data(), 1, n_chunks), std::runtime_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(map_storage_movable, T, storage_data_types)
{
    size_t n_chunks = 5;
    size_t chunk_data_size = 1000;
    T meta_init_val = 127;

    {
        auto filename = get_random_temp_file();

        // Create storage A and fill in some random chunks
        MmapStorage<T> map_storage_a(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);

        std::vector<std::vector<unsigned char>> chunks;
        for (size_t i = 0; i < n_chunks; i++) {
            chunks.push_back(generate_random_string(chunk_data_size));
            map_storage_a.Insert(chunks.back().data(), i, i);
        }

        // Create storage B and move A into B
        MmapStorage<T> map_storage_b(std::move(map_storage_a));

        // Once storage A is in moved-from state, it should no longer be able to
        // remove the memory-mapped storage file
        map_storage_a.Remove();
        BOOST_CHECK(fs::exists(filename));

        // Confirm that B has the contents moved from A
        BOOST_CHECK(map_storage_b.Size() == ((chunk_data_size + sizeof(T)) * n_chunks));
        BOOST_CHECK(map_storage_b.IsRecoverable() == false);
        BOOST_CHECK(map_storage_b.GetStorage() != nullptr);
        BOOST_CHECK(map_storage_a.GetStorage() == nullptr);
        for (size_t i = 0; i < n_chunks; i++) {
            check_chunk_equal(map_storage_b.GetChunk(i), chunks[i], chunk_data_size);
            BOOST_CHECK(map_storage_b.GetChunkMeta(i) == (T)i);
        }

        // Storage B can remove the memory-mapped file
        map_storage_b.Remove();
        BOOST_CHECK(!fs::exists(filename));
    }

    // Check that the recoverable state can be moved
    {
        auto filename = get_random_temp_file();

        MmapStorage<T> map_storage_a(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
        auto random_data = generate_random_string(chunk_data_size);
        map_storage_a.Insert(random_data.data(), 0, 0);

        MmapStorage<T> map_storage_b(filename, true /* create */, chunk_data_size, n_chunks, meta_init_val);
        BOOST_CHECK(map_storage_b.IsRecoverable());

        MmapStorage<T> map_storage_c(std::move(map_storage_b));
        BOOST_CHECK(map_storage_c.IsRecoverable());
    }
}


BOOST_AUTO_TEST_SUITE_END()
