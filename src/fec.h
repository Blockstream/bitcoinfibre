// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_FEC_H
#define BITCOIN_FEC_H

#include <assert.h>
#include <memory>
#include <stdint.h>
#include <vector>
#include <fs.h>

#define FEC_CHUNK_SIZE 1152
#define CHUNK_ID_SIZE sizeof(uint32_t)
#define CM256_MAX_CHUNKS 27
#define FEC_CHUNK_COUNT_MAX (1 << 24)

#include "wirehair/wirehair.h"
#include "wirehair/cm256.h"
#include "random.h"
#include "open_hash_set.h"

typedef std::aligned_storage<FEC_CHUNK_SIZE, 16>::type FECChunkType;
static_assert(FEC_CHUNK_SIZE % 16 == 0, "Padding of FECChunkType may hurt performance, and really shouldn't be required");
static_assert(sizeof(FECChunkType) == FEC_CHUNK_SIZE, "Padding of FECChunkType may hurt performance, and really shouldn't be required");

class BlockChunkRecvdTracker {
private:
    std::vector<bool> data_chunk_recvd_flags; // Used only for data chunks

    struct ChunkIdHasher {
        uint64_t operator()(const uint32_t elem) const { return elem; }
    };
    struct ChunkIdIsNull {
        bool operator()(const uint32_t elem) const { return elem == 0; }
    };
    open_hash_set<uint32_t, ChunkIdIsNull, ChunkIdHasher> fec_chunks_recvd;

public:
    BlockChunkRecvdTracker() {} // dummy - dont use something created like this
    BlockChunkRecvdTracker(size_t data_chunks);
    BlockChunkRecvdTracker(const BlockChunkRecvdTracker& o) =delete;
    BlockChunkRecvdTracker(BlockChunkRecvdTracker&& o) =delete;
    BlockChunkRecvdTracker& operator=(BlockChunkRecvdTracker&& other) noexcept;

    inline bool CheckPresentAndMarkRecvd(uint32_t chunk_id) {
        if (chunk_id < data_chunk_recvd_flags.size()) {
            if (data_chunk_recvd_flags[chunk_id])
                return true;
            data_chunk_recvd_flags[chunk_id] = true;
        } else {
            if (fec_chunks_recvd.find_fast(chunk_id))
                return true;
            if (!fec_chunks_recvd.insert(chunk_id).second)
                return true;
        }

        return false;
    }

    inline bool CheckPresent(uint32_t chunk_id) const {
        if (chunk_id < data_chunk_recvd_flags.size()) return data_chunk_recvd_flags[chunk_id];
        return fec_chunks_recvd.find_fast(chunk_id);
    }
};

class FECDecoder;
class FECEncoder {
private:
    WirehairCodec wirehair_encoder = NULL;
    const std::vector<unsigned char>* data;
    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunks;
    int32_t cm256_start_idx = -1;
    FastRandomContext rand;

    // Used only in cm256 mode:
    FECChunkType tmp_chunk;
    cm256_block cm256_blocks[CM256_MAX_CHUNKS];

public:
    // dataIn/fec_chunksIn must not change during lifetime of this object
    // fec_chunks->second[i] must be 0 for all i!
    FECEncoder(const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn);
    FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn);
    ~FECEncoder();

    FECEncoder(const FECEncoder&) = delete;
    FECEncoder(FECEncoder&&) = delete;

    /**
     * After BuildChunk(i), fec_chunks->first[i] will be filled with FEC data
     * and fec_chunks->second[i] will have a random chunk_id suitable to be
     * passed directly into FECDecoder::ProvideChunk or FECDecoder::HasChunk
     * (ie it will be offset by the data chunk count).
     */
    bool BuildChunk(size_t vector_idx, bool overwrite=false);
    bool PrefillChunks();
};

enum class MemoryUsageMode : bool {
    USE_MEMORY = false,
    USE_MMAP = true
};

class MapStorage
{
public:
    MapStorage(boost::filesystem::path const& p, int const c, bool create = false);
    MapStorage(MapStorage&& ms) noexcept;

    void Insert(const unsigned char* chunk, uint32_t chunk_id, size_t idx);
    char* GetChunk(size_t idx) const;
    uint32_t GetChunkId(size_t idx) const;
    size_t Size() const;
    char* GetStorage() const { return m_data_storage; }

    ~MapStorage();

private:
    size_t m_chunk_count = 0;
    int m_chunk_file = -1;
    char* m_data_storage = nullptr;
    char* m_id_storage = nullptr;
    size_t m_file_size = 0;
};

class FECDecoder {
    FECChunkType tmp_chunk;
    size_t chunk_count = 0;
    size_t chunks_recvd = 0;
    size_t obj_size = 0;
    mutable bool decodeComplete = false;
    BlockChunkRecvdTracker chunk_tracker;

    // Only used in wirehair mode:
    WirehairCodec wirehair_decoder = nullptr;

    // whether this instance is expected to delete the file or not, when
    // destructed
    bool owns_file = false;

    // Whether to store chunk ids and chunk data in memory (e.g. vector) or
    // to store them in a memory mapped file on the disk
    MemoryUsageMode memory_usage_mode = MemoryUsageMode::USE_MMAP;

    // maps final chunk ids to offset into the storage (backed by the file)
    std::vector<uint8_t> cm256_map;

    bool cm256_decoded = false;
    // Only used in cm256 mode:
    std::vector<FECChunkType> cm256_chunks;
    cm256_block cm256_blocks[CM256_MAX_CHUNKS];

    void remove_file();

    // filename for the chunk storage
    fs::path filename;

    friend FECEncoder::FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn);

    fs::path compute_filename() const;

    bool ProvideChunkMemory(const unsigned char* chunk, uint32_t chunk_id);
    bool ProvideChunkMmap(const unsigned char* chunk, uint32_t chunk_id);

    void DecodeCm256();
    void DecodeCm256Memory();
    void DecodeCm256Mmap();

public:
    // data_size must be <= MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR
    // memory_usage_mode if set to USE_MEM, all chunks and chunk ids are stored in a memory-mapped file on disk
    //                  if set to USE_MEMORY, nothing is stored on disk and everything will live in the memory
    FECDecoder(size_t data_size, MemoryUsageMode memory_usage_mode = MemoryUsageMode::USE_MMAP);

    FECDecoder();
    ~FECDecoder();

    FECDecoder(const FECDecoder&) =delete;
    FECDecoder(FECDecoder&& decoder) =delete;
    FECDecoder& operator=(FECDecoder&& decoder) noexcept;

    bool ProvideChunk(const unsigned char* chunk, uint32_t chunk_id);
    bool ProvideChunk(const FECChunkType* chunk, uint32_t chunk_id) { return ProvideChunk((const unsigned char*)chunk, chunk_id); }

    bool HasChunk(uint32_t chunk_id);
    bool DecodeReady() const;
    const void* GetDataPtr(uint32_t chunk_id); // Only valid until called again
    size_t GetChunkCount() const { return chunk_count; }
    size_t GetChunksRcvd() const { return chunks_recvd; }
    fs::path GetFileName() const { return filename; }

};

bool BuildFECChunks(const std::vector<unsigned char>& data, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>& fec_chunks);

#endif
