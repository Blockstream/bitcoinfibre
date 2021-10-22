#ifndef BITCOIN_MMAP_STORAGE_H
#define BITCOIN_MMAP_STORAGE_H

#include "exchange.h"
#include <boost/filesystem.hpp>
#include <fcntl.h>
#include <sys/mman.h>

/**
 * @brief Handler for chunked-data storage on memory-mapped file
 *
 * This class handles the memory-mapped storage of a data structure that has
 * been divided into equal-sized chunks. It provides methods to insert and
 * retrieve each chunk of data independently. Furthermore, it considers that
 * each chunk can have some associated metadata, which can also be stored and
 * retrieved in/from the memory-mapped file.
 *
 * This class creates the mmapped file if so desired. If not, it merely opens
 * the mmapped file and handles the insertion/retrieval of data.
 *
 * @tparam T Type associated with the metadata stored for each chunk of data.
 */
template <typename T>
class MmapStorage
{
public:
    /**
     * @brief Construct the mmap storage handler
     * @param file_path Path to the mmapped file.
     * @param create Whether to create the mmapped file.
     * @param chunk_data_size Data chunk size.
     * @param chunk_count Chunk count.
     * @param meta_init_val Initialization value set for each chunk metadata.
     *
     * @note meta_init_val should be set to an invalid value that is not
     * expected to occurr in runtime. This invalid value is ultimately used to
     * infer when the mmapped file has pre-existing (already initialized)
     * data. See "Recoverable()".
     */
    MmapStorage(boost::filesystem::path const& file_path, bool create, size_t const chunk_data_size, size_t const chunk_count, T meta_init_val) : m_file_path(file_path),
                                                                                                                                                  m_chunk_data_size(chunk_data_size),
                                                                                                                                                  m_chunk_count(chunk_count),
                                                                                                                                                  m_file_size((m_chunk_data_size + sizeof(T)) * chunk_count),
                                                                                                                                                  m_meta_init_val(meta_init_val)
    {
        if (create) {
            fs::create_directories(m_file_path.parent_path());
        }

        const int flags = create ? (O_RDWR | O_CREAT) : O_RDWR;
        const int chunk_file = ::open(m_file_path.c_str(), flags, 0755);
        if (chunk_file == -1) {
            throw std::runtime_error("failed to open file: " + m_file_path.string() + " " + ::strerror(errno));
        }

        // Convention: data chunks are stored first, while the metadata is
        // stored by the end of the mmapped file.
        m_data_storage = static_cast<char*>(::mmap(nullptr, m_file_size,
                                                   PROT_READ | PROT_WRITE, MAP_SHARED, chunk_file, 0));
        if (m_data_storage == MAP_FAILED) {
            ::close(chunk_file);
            throw std::runtime_error("mmap failed " + m_file_path.string() + " " + ::strerror(errno));
        }
        m_meta_storage = m_data_storage + (m_chunk_count * m_chunk_data_size);

        // When creating the mmap file, try to recover pre-existing data
        // first. If not available, create and initialize the metadata with the
        // given initial value. Otherwise (if recovery data is available), let
        // the caller handle the recovery and do not initialize any metadata.
        if (create) {
            m_recoverable = Recoverable();
            if (!m_recoverable) {
                int const ret = ::ftruncate(chunk_file, m_file_size);
                if (ret != 0) {
                    ::unlink(m_file_path.c_str());
                    throw std::runtime_error("ftruncate failed " + m_file_path.string() + " " + ::strerror(errno));
                }

                for (size_t i = 0; i < m_chunk_count; i++) {
                    memcpy(m_meta_storage + (i * sizeof(T)), &m_meta_init_val, sizeof(T));
                }
            }
        }

        // After the mmap() call, the file descriptor can be closed without
        // invalidating the mapping.
        ::close(chunk_file);
    }

    MmapStorage(MmapStorage&& ms) noexcept : m_file_path(std::move(ms.m_file_path)),
                                             m_chunk_data_size(ms.m_chunk_data_size),
                                             m_chunk_count(ms.m_chunk_count),
                                             m_file_size(ms.m_file_size),
                                             m_meta_init_val(std::move(ms.m_meta_init_val)),
                                             m_data_storage(exchange(ms.m_data_storage, nullptr)),
                                             m_meta_storage(exchange(ms.m_meta_storage, nullptr)),
                                             m_recoverable(ms.m_recoverable)
    {
        ms.m_file_path.clear();
    }

    /**
     * @brief Insert new chunk and metadata into the mmapped storage.
     * @param chunk Data chunk.
     * @param chunk_meta Metadata associated with the data chunk.
     * @param idx Data chunk index.
     * @return Void.
     */
    void Insert(const unsigned char* chunk, T chunk_meta, size_t idx)
    {
        memcpy(GetChunk(idx), chunk, m_chunk_data_size);
        memcpy(m_meta_storage + (idx * sizeof(T)), &chunk_meta, sizeof(T));
    }

    /**
     * @brief Get chunk stored in a given index.
     * @param idx Chunk index.
     * @return Pointer to chunk data.
     */
    char* GetChunk(size_t idx) const
    {
        if (idx < m_chunk_count) {
            return m_data_storage + (idx * m_chunk_data_size);
        }
        throw std::runtime_error("Invalid chunk index: " + std::to_string(idx));
    }

    /**
     * @brief Get the metadata associated with a given chunk.
     * @param idx Chunk index.
     * @return Chunk metadata.
     */
    T GetChunkMeta(size_t idx) const
    {
        if (idx < m_chunk_count) {
            T chunk_meta;
            memcpy(&chunk_meta, m_meta_storage + (idx * sizeof(T)), sizeof(T));
            return chunk_meta;
        }
        throw std::runtime_error("Invalid chunk index: " + std::to_string(idx));
    }

    /**
     * @brief Get file size.
     * @return File size.
     */
    size_t Size() const { return m_file_size; }

    /**
     * @brief Get pointer to mmapped storage.
     * @return Mmap storage pointer.
     */
    char* GetStorage() const { return m_data_storage; }

    /**
     * @brief Check if the underlying storage is recoverable from a pre-existing file.
     * @note Return value is only valid if instantiating MmapStorage with 'create=true'.
     */
    bool IsRecoverable() const { return m_recoverable; }

    /**
     * @brief Remove the mmapped file
     * @note The implementation uses unlink(), which possibly removes the file
     * but not necessarily.
     */
    void Remove()
    {
        if (m_data_storage != nullptr && !m_file_path.empty()) {
            ::madvise(m_data_storage, m_file_size, MADV_REMOVE);
            ::unlink(m_file_path.c_str());
        }
    }

    /**
     * @brief Destroy the object and unmap the memory region.
     * @note This destructor does not remove the underlying file.
     */
    ~MmapStorage()
    {
        if (m_data_storage != nullptr)
            ::munmap(m_data_storage, m_file_size);
    }

private:
    /**
     * @brief Check if possible to recover data from a pre-existing storage file.
     *
     * Infer that a given file has recoverable data when:
     *
     * 1) A file with the same name already exists.
     * 2) The pre-existing file size matches with the target size.
     * 3) The metadata storage has entries differing from the pre-specified
     *    initialization value defined on the constructor (i.e., entries that
     *    are already initialized).
     *
     * @return Whether possible to recover pre-existing data.
     */
    bool Recoverable() const
    {
        if (m_file_path.empty() || !fs::exists(m_file_path)) {
            return false;
        }

        size_t chunk_file_size = fs::file_size(m_file_path);
        if (chunk_file_size == 0 || chunk_file_size != m_file_size || m_chunk_count == 0) {
            return false;
        }

        // At least one chunk id should have a valid value (i.e., not equal to
        // m_meta_init_val), otherwise the file does not have useful data
        for (size_t i = 0; i < m_chunk_count; i++) {
            if (GetChunkMeta(i) != m_meta_init_val) {
                return true;
            }
        }
        return false;
    }


private:
    boost::filesystem::path m_file_path;
    size_t m_chunk_data_size = 0;
    size_t m_chunk_count = 0;
    size_t m_file_size = 0;
    T m_meta_init_val;
    char* m_data_storage = nullptr;
    char* m_meta_storage = nullptr;
    bool m_recoverable = false;
};

#endif
