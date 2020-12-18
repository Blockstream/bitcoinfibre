// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <fec.h>
#include <logging.h>
#include <consensus/consensus.h> // for MAX_BLOCK_SERIALIZED_SIZE
#include <blockencodings.h> // for MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR
#include <util/system.h>

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fs.h>

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

#define CHUNK_COUNT_USES_CM256(chunks) ((chunks) >= 2 && (chunks) <= CM256_MAX_CHUNKS)
#define CHUNK_COUNT_USES_WIREHAIR(chunks) ((chunks) > CM256_MAX_CHUNKS)

#define CACHE_STATES_COUNT 5


static std::atomic<WirehairCodec> cache_states[CACHE_STATES_COUNT];
static inline WirehairCodec get_wirehair_codec() {
    for (size_t i = 0; i < CACHE_STATES_COUNT; i++) {
        WirehairCodec state = cache_states[i].exchange(nullptr);
        if (state) {
            return state;
        }
    }
    return nullptr;
}
static inline void return_wirehair_codec(WirehairCodec state) {
    WirehairCodec null_state = nullptr;
    for (size_t i = 0; i < CACHE_STATES_COUNT; i++) {
        if (cache_states[i].compare_exchange_weak(null_state, state)) {
            return;
        }
    }
    wirehair_free(state);
}

BlockChunkRecvdTracker::BlockChunkRecvdTracker(size_t chunk_count) :
        data_chunk_recvd_flags(CHUNK_COUNT_USES_CM256(chunk_count) ? 0xff : chunk_count),
        fec_chunks_recvd(CHUNK_COUNT_USES_CM256(chunk_count) ? 1 : chunk_count) { }

BlockChunkRecvdTracker& BlockChunkRecvdTracker::operator=(BlockChunkRecvdTracker&& other) noexcept {
    data_chunk_recvd_flags = std::move(other.data_chunk_recvd_flags);
    fec_chunks_recvd       = std::move(other.fec_chunks_recvd);
    return *this;
}

namespace {

template <typename T>
T exchange(T& var, T&& new_value)
{
    T tmp = std::move(var);
    var = std::move(new_value);
    return tmp;
}

template <typename T>
T* exchange(T*& var, nullptr_t)
{
    T* tmp = std::move(var);
    var = nullptr;
    return tmp;
}
}


MapStorage::MapStorage(boost::filesystem::path const& p, int const c, bool create) :
    m_chunk_count(c),
    m_file_size((CHUNK_ID_SIZE + FEC_CHUNK_SIZE) * c)
{
    if (create) {
        fs::create_directories(p.parent_path());
    }

    const int flags = create ? (O_RDWR | O_CREAT) : O_RDWR;
    m_chunk_file = ::open(p.c_str(), flags, 0755);
    if (m_chunk_file == -1) {
        throw std::runtime_error("failed to open file: " + p.string() + " " + ::strerror(errno));
    }

    if (create) {
        int const ret = ::ftruncate(m_chunk_file, (CHUNK_ID_SIZE + FEC_CHUNK_SIZE) * m_chunk_count);
        if (ret != 0) {
            ::unlink(p.c_str());
            throw std::runtime_error("ftruncate failed " + p.string() + " " + ::strerror(errno));
        }
    } else {
        m_data_storage = static_cast<char*>(::mmap(nullptr, m_file_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, m_chunk_file, 0));
        if (m_data_storage == MAP_FAILED) {
            ::close(m_chunk_file);
            throw std::runtime_error("mmap failed " + p.string() + " " + ::strerror(errno));
        }
        m_id_storage = m_data_storage + (m_chunk_count * FEC_CHUNK_SIZE);
    }
}

MapStorage::MapStorage(MapStorage&& ms) noexcept :
    m_chunk_count(ms.m_chunk_count),
    m_chunk_file(exchange(ms.m_chunk_file, -1)),
    m_data_storage(exchange(ms.m_data_storage, nullptr))
{}

void MapStorage::Insert(const unsigned char* chunk, uint32_t chunk_id, size_t idx)
{
    memcpy(GetChunk(idx), chunk, FEC_CHUNK_SIZE);

    // store chunk_id at the end of the file
    auto const chunk_id_dest_ptr = m_id_storage + (idx * CHUNK_ID_SIZE);
    memcpy(chunk_id_dest_ptr, &chunk_id, CHUNK_ID_SIZE);
}

char* MapStorage::GetChunk(size_t idx) const
{
    if (idx < m_chunk_count) {
        return m_data_storage + (idx * FEC_CHUNK_SIZE);
    }
    throw std::runtime_error("Invalid chunk index: " + idx);
}

uint32_t MapStorage::GetChunkId(size_t idx) const
{
    if (idx < m_chunk_count) {
        uint32_t chunk_id = 0;
        memcpy(&chunk_id, m_id_storage + (idx * CHUNK_ID_SIZE), CHUNK_ID_SIZE);
        return chunk_id;
    }
    throw std::runtime_error("Invalid chunk id index: " + idx);
}

size_t MapStorage::Size() const
{
    return m_file_size;
}

MapStorage::~MapStorage()
{
    if (m_data_storage != nullptr)
        ::munmap(m_data_storage, m_file_size);
    if (m_chunk_file != -1)
        ::close(m_chunk_file);
}

FECDecoder::FECDecoder()
{
}

FECDecoder::FECDecoder(size_t const data_size, MemoryUsageMode memory_mode, const std::string& obj_id) :
        chunk_count(DIV_CEIL(data_size, FEC_CHUNK_SIZE)),
        obj_size(data_size),
        chunk_tracker(chunk_count),
        memory_usage_mode(memory_mode)
{
    if (chunk_count < 2)
        return;

    if (memory_usage_mode == MemoryUsageMode::USE_MMAP) {
        filename = compute_filename(obj_id);
        MapStorage map_storage(filename, chunk_count, true /* create */);
        owns_file = true;
    } else {
        if (CHUNK_COUNT_USES_CM256(chunk_count)) {
            cm256_chunks.reserve(chunk_count);
        } else {
            wirehair_decoder = wirehair_decoder_create(get_wirehair_codec(), data_size, FEC_CHUNK_SIZE);
            assert(wirehair_decoder);
        }
    }
}

fs::path FECDecoder::compute_filename(const std::string& obj_id) const
{
    // Try to make a unique name out of the available information
    if (obj_id.empty()) {
        return GetDataDir() / "partial_blocks" / std::to_string(std::uintptr_t(this));
    } else {
        // filename pattern = <obj_id>_<obj_size>
        return GetDataDir() / "partial_blocks" / (obj_id + "_" + std::to_string(obj_size));
    }
}

FECDecoder& FECDecoder::operator=(FECDecoder&& decoder) noexcept {
    if (owns_file)
        remove_file();
    if (wirehair_decoder)
        return_wirehair_codec(wirehair_decoder);

    chunk_count       = decoder.chunk_count;
    chunks_recvd      = decoder.chunks_recvd;
    obj_size          = decoder.obj_size;
    decodeComplete    = decoder.decodeComplete;
    chunk_tracker     = std::move(decoder.chunk_tracker);
    owns_file         = exchange(decoder.owns_file, false);
    memory_usage_mode = decoder.memory_usage_mode;
    cm256_map         = std::move(decoder.cm256_map);
    cm256_decoded     = exchange(decoder.cm256_decoded, false);
    cm256_chunks      = std::move(decoder.cm256_chunks);
    if (owns_file) {
	    assert(fs::exists(decoder.filename));
        if (filename.empty()) {
            filename = decoder.filename;
        } else {
            fs::rename(decoder.filename, filename);
        }
    }
    tmp_chunk        = decoder.tmp_chunk;
    wirehair_decoder = exchange(decoder.wirehair_decoder, nullptr);

    // In mmap mode, cm256_blocks are populated within DecodeCm256Mmap, when the
    // object is already decodable. In contrast, in memory mode, cm256_blocks
    // are populated on every call to ProvideChunkMemory().
    if (memory_usage_mode == MemoryUsageMode::USE_MEMORY || cm256_decoded) {
        memcpy(cm256_blocks, decoder.cm256_blocks, sizeof(cm256_block) * decoder.chunks_recvd);
    }

    return *this;
}

void FECDecoder::remove_file()
{
    if (memory_usage_mode == MemoryUsageMode::USE_MMAP) {
        MapStorage map_storage(filename, chunk_count);
        ::madvise(map_storage.GetStorage(), map_storage.Size(), MADV_REMOVE);
        ::unlink(filename.c_str());
    }
    owns_file = false;
}

FECDecoder::~FECDecoder() {
    if (wirehair_decoder)
        return_wirehair_codec(wirehair_decoder);

    if (owns_file)
        remove_file();
}

bool FECDecoder::ProvideChunk(const unsigned char* const chunk, uint32_t const chunk_id) {
    if (CHUNK_COUNT_USES_CM256(chunk_count) ? chunk_id > 0xff : chunk_id > FEC_CHUNK_COUNT_MAX)
        return false;

    if (decodeComplete)
        return true;

    // wirehair breaks if we call it twice with the same packet
    if (chunk_tracker.CheckPresentAndMarkRecvd(chunk_id))
        return true;

    if (chunk_count < 2) { // For 1-packet data, just send it repeatedly...
        memcpy(&tmp_chunk, chunk, FEC_CHUNK_SIZE);
        decodeComplete = true;
        return true;
    }

    if (memory_usage_mode == MemoryUsageMode::USE_MMAP) {
        return ProvideChunkMmap(chunk, chunk_id);
    } else {
        return ProvideChunkMemory(chunk, chunk_id);
    }
}


bool FECDecoder::ProvideChunkMmap(const unsigned char* chunk, uint32_t chunk_id)
{
    MapStorage map_storage(filename, chunk_count);

    // both wirehair and cm256 need chunk_count chunks, so regardless of
    // which decoder we use, fill our chunk storage
    if (chunks_recvd < chunk_count) {
        map_storage.Insert(chunk, chunk_id, chunks_recvd);
    }

    // CM256 is an MDS code. Hence, as soon as chunk_count chunks are available,
    // the CM256-encoded object is guaranteed to be decodable already. In
    // contrast, wirehair is not MDS and may need a few extra chunks.
    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        if (chunk_count == chunks_recvd + 1) {
            decodeComplete = true;
        }
    } else {
        if (chunks_recvd + 1 == chunk_count) {
            // This was the "last" chunk. Now try to decode them!
            // this will potentially pull chunks back in from disk
            wirehair_decoder = wirehair_decoder_create(get_wirehair_codec(), obj_size, FEC_CHUNK_SIZE);
            assert(wirehair_decoder);

            for (size_t i = 0; i < chunk_count; ++i) {
                const WirehairResult decode_res = wirehair_decode(wirehair_decoder, map_storage.GetChunkId(i), map_storage.GetChunk(i), FEC_CHUNK_SIZE);
                if (decode_res == Wirehair_Success) {
                    decodeComplete = true;
                    break;
                } else if (decode_res != Wirehair_NeedMore) {
                    LogPrintf("wirehair_decode failed: %s\n", wirehair_result_string(decode_res));
                    return false;
                }
            }
        } else if (chunks_recvd >= chunk_count) {
            // if we've received chunk_count chunks already, we will have
            // tried to decode. If we get here it means we failed to decode,
            // but we've already put everything in RAM, so we might as well
            // continue trying to decode as we go now. No need to use
            // chunk_storage
            assert(wirehair_decoder);
            const WirehairResult decode_res = wirehair_decode(wirehair_decoder, chunk_id, (void*)chunk, FEC_CHUNK_SIZE);
            if (decode_res == Wirehair_Success) {
                decodeComplete = true;
            } else if (decode_res != Wirehair_NeedMore) {
                LogPrintf("wirehair_decode failed: %s\n", wirehair_result_string(decode_res));
                return false;
            }
        }
    }

    ++chunks_recvd;

    return true;
}


bool FECDecoder::ProvideChunkMemory(const unsigned char* chunk, uint32_t chunk_id)
{
    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        cm256_chunks.emplace_back();
        memcpy(&cm256_chunks.back(), chunk, FEC_CHUNK_SIZE);
        cm256_blocks[chunks_recvd].Block = &cm256_chunks.back();
        cm256_blocks[chunks_recvd].Index = (uint8_t)chunk_id;
        if (chunk_count == chunks_recvd + 1){
            decodeComplete = true;
        }
    } else {
        const WirehairResult decode_res = wirehair_decode(wirehair_decoder, chunk_id, (void*)chunk, FEC_CHUNK_SIZE);
        if (decode_res == Wirehair_Success)
            decodeComplete = true;
        else {
            if (decode_res != Wirehair_NeedMore) {
                LogPrintf("wirehair_decode failed: %s\n", wirehair_result_string(decode_res));
                return false;
            }
        }
    }

    chunks_recvd++;
    return true;
}

bool FECDecoder::HasChunk(uint32_t chunk_id) {
    if (CHUNK_COUNT_USES_CM256(chunk_count) ? chunk_id > 0xff : chunk_id > FEC_CHUNK_COUNT_MAX)
        return false;

    return decodeComplete || chunk_tracker.CheckPresent(chunk_id);
}

bool FECDecoder::DecodeReady() const {
    return decodeComplete;
}

const void* FECDecoder::GetDataPtr(uint32_t chunk_id)
{
    assert(DecodeReady());
    assert(chunk_id < chunk_count);
    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        if (!cm256_decoded) {
            DecodeCm256();
        }
        if (memory_usage_mode == MemoryUsageMode::USE_MMAP) {
            assert(chunk_id < cm256_map.size());
            assert(cm256_map[chunk_id] < chunk_count);
            MapStorage map_storage(filename, chunk_count);
            memcpy(&tmp_chunk, map_storage.GetChunk(cm256_map[chunk_id]), FEC_CHUNK_SIZE);
        } else {
            assert(cm256_blocks[uint8_t(chunk_id)].Index == chunk_id);
            return cm256_blocks[uint8_t(chunk_id)].Block;
        }
    } else if (CHUNK_COUNT_USES_WIREHAIR(chunk_count)) {
        uint32_t chunk_size = FEC_CHUNK_SIZE;
        assert(!wirehair_recover_block(wirehair_decoder, chunk_id, (void*)&tmp_chunk, &chunk_size));
    }
    return &tmp_chunk;
}

std::vector<unsigned char> FECDecoder::GetDecodedData()
{
    assert(DecodeReady());
    std::vector<unsigned char> vec(obj_size);
    if (chunk_count == 1) {
        memcpy(vec.data(), &tmp_chunk, obj_size);
    } else if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        for (uint32_t i = 0; i < chunk_count; i++) {
            const void* data_ptr = GetDataPtr(i);
            assert(data_ptr);
            size_t size_remaining = obj_size - (i * FEC_CHUNK_SIZE);
            memcpy(vec.data() + (i * FEC_CHUNK_SIZE), data_ptr, std::min(size_remaining, (size_t)FEC_CHUNK_SIZE));
        }
    } else {
        WirehairResult decode_res = wirehair_recover(wirehair_decoder, vec.data(), obj_size);
        if (decode_res != Wirehair_Success) {
            throw std::runtime_error("Wirehair decoding failed");
        }
    }
    return vec;
}

void FECDecoder::DecodeCm256()
{
    assert(!cm256_decoded);
    if (memory_usage_mode == MemoryUsageMode::USE_MMAP) {
        DecodeCm256Mmap();
    } else {
        DecodeCm256Memory();
    }
    cm256_decoded = true;
}

void FECDecoder::DecodeCm256Memory()
{
    cm256_encoder_params params{(int)chunk_count, (256 - (int)chunk_count - 1), FEC_CHUNK_SIZE};
    assert(!cm256_decode(params, cm256_blocks));
    std::sort(cm256_blocks, &cm256_blocks[chunk_count], [](const cm256_block& a, const cm256_block& b) { return a.Index < b.Index; });
}

void FECDecoder::DecodeCm256Mmap()
{
    MapStorage map_storage(filename, chunk_count);
    char* chunk_storage = map_storage.GetStorage();

    // Fill in cm256 chunks in the order they were received. These
    // can consist of both original and recovery chunks.
    for (size_t i = 0; i < chunk_count; ++i) {
        cm256_blocks[i].Block = map_storage.GetChunk(i);
        cm256_blocks[i].Index = (uint8_t)map_storage.GetChunkId(i);
    }
    cm256_encoder_params params{(int)chunk_count, (256 - (int)chunk_count - 1), FEC_CHUNK_SIZE};
    assert(!cm256_decode(params, cm256_blocks));
    cm256_map.resize(chunk_count);
    // After decoding, the cm256_blocks should not contain recovery
    // chunks anymore. Instead, they should contain the original
    // (decoded) chunks, so that their Index (chunk id) and Block
    // (pointer) fields should correspond, respectively, to the
    // original chunk id and the original data decoded in place
    // within the chunk_storage. However, the order of cm256_blocks
    // may not be sorted, so map each decoded chunk index to the
    // corresponding index in the storage.
    for (size_t i = 0; i < chunk_count; ++i) {
        auto const& b = cm256_blocks[i];
        assert(b.Index < CM256_MAX_CHUNKS);
        cm256_map[b.Index] = (static_cast<char*>(b.Block) - chunk_storage) / FEC_CHUNK_SIZE;
    }
}

FECEncoder::FECEncoder(const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn)
        : data(dataIn), fec_chunks(fec_chunksIn) {
    assert(!fec_chunks->second.empty());
    assert(!data->empty());

    size_t chunk_count = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    if (chunk_count < 2)
        return;

    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        for (uint8_t i = 0; i < chunk_count - 1; i++) {
            cm256_blocks[i] = cm256_block { const_cast<unsigned char*>(data->data()) + i * FEC_CHUNK_SIZE, i };
        }
        size_t expected_size = chunk_count * FEC_CHUNK_SIZE;
        if (expected_size == data->size()) {
            cm256_blocks[chunk_count - 1] = cm256_block { const_cast<unsigned char*>(data->data()) + (chunk_count - 1) * FEC_CHUNK_SIZE, (uint8_t)(chunk_count - 1) };
        } else {
            size_t fill_size = expected_size - data->size();
            memcpy(&tmp_chunk, data->data() + (chunk_count - 1) * FEC_CHUNK_SIZE, FEC_CHUNK_SIZE - fill_size);
            memset(((unsigned char*)&tmp_chunk) + FEC_CHUNK_SIZE - fill_size, 0, fill_size);
            cm256_blocks[chunk_count - 1] = cm256_block { &tmp_chunk, (uint8_t)(chunk_count - 1) };
        }
    } else {
        wirehair_encoder = wirehair_encoder_create(get_wirehair_codec(), data->data(), data->size(), FEC_CHUNK_SIZE);
        assert(wirehair_encoder);
    }
}

FECEncoder::FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn)
        : data(dataIn), fec_chunks(fec_chunksIn) {
    assert(!fec_chunks->second.empty());
    assert(!data->empty());

    size_t chunk_count = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    if (chunk_count < 2)
        return;

    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        for (uint8_t i = 0; i < chunk_count - 1; i++) {
            cm256_blocks[i] = cm256_block { const_cast<unsigned char*>(data->data()) + i * FEC_CHUNK_SIZE, i };
        }
        size_t expected_size = chunk_count * FEC_CHUNK_SIZE;
        if (expected_size == data->size()) {
            cm256_blocks[chunk_count - 1] = cm256_block { const_cast<unsigned char*>(data->data()) + (chunk_count - 1) * FEC_CHUNK_SIZE, (uint8_t)(chunk_count - 1) };
        } else {
            size_t fill_size = expected_size - data->size();
            memcpy(&tmp_chunk, data->data() + (chunk_count - 1) * FEC_CHUNK_SIZE, FEC_CHUNK_SIZE - fill_size);
            memset(((unsigned char*)&tmp_chunk) + FEC_CHUNK_SIZE - fill_size, 0, fill_size);
            cm256_blocks[chunk_count - 1] = cm256_block { &tmp_chunk, (uint8_t)(chunk_count - 1) };
        }
    } else {
        wirehair_encoder = decoder.wirehair_decoder;
        decoder.wirehair_decoder = nullptr;

        assert(!wirehair_decoder_becomes_encoder(wirehair_encoder));
        assert(wirehair_encoder);
    }
}

FECEncoder::~FECEncoder() {
    if (wirehair_encoder)
        return_wirehair_codec(wirehair_encoder);
}

/**
 * Build FEC chunk
 *
 * Depending on the total number of chunks (of FEC_CHUNK_SIZE bytes) composing
 * the original data object, one of the following coding schemes will be used:
 *
 * 1) Repetition coding: if object fits in a single chunk
 * 2) cm256: if object has number of chunks up to CM256_MAX_CHUNKS
 * 3) wirehair: if object has number of chunks greater than CM256_MAX_CHUNKS
 *
 * cm256 is a maximum distance separable (MDS), so it always recovers N original
 * data chunks from N coded chunks. However, it supports up to 256 chunks only,
 * so it works best with shorter data. In contrast, wirehair works better with
 * longer data. Nevertheless, wirehair is not MDS. On average, it requires N +
 * 0.02 coded chunks to recover N uncoded chunks.
 *
 * Parameter `vector_idx` is the index within the array of FEC chunks that are
 * supposed to be produced. For each such chunk, a chunk id will be
 * generated. For wirehair coding, the chunk id is random. The motivation is
 * that we want receivers to get a different chunk id every time. For cm256, the
 * chunk_id is determistic, more specifically `vector_idx` + a random
 * offset. For repetition coding, it is also deterministic.
 *
 * Parameter `overwrite` allows regeneration of a FEC chunk on a given
 * `vector_idx` even when another chunk already exists in this index.
 *
 */
bool FECEncoder::BuildChunk(size_t vector_idx, bool overwrite) {
    if (vector_idx >= fec_chunks->second.size())
         throw std::runtime_error("Invalid vector_idx");

    if (!overwrite && fec_chunks->second[vector_idx])
        return true;

    size_t data_chunks = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    if (data_chunks < 2) { // When the original data fits in 1 chunk, just send it repeatedly...
        memcpy(&fec_chunks->first[vector_idx], &(*data)[0], data->size());
        memset(((char*)&fec_chunks->first[vector_idx]) + data->size(), 0, FEC_CHUNK_SIZE - data->size());
        fec_chunks->second[vector_idx] = vector_idx; // chunk_id
        return true;
    }

    uint32_t fec_chunk_id;
    // wh256 supports either unlimited chunks, or up to 256 incl data chunks
    // if data_chunks < 28 (as it switches to cm256 mode)
    if (CHUNK_COUNT_USES_CM256(data_chunks)) {
        if (cm256_start_idx == -1)
            cm256_start_idx = GetRand(0xff);
        fec_chunk_id = (cm256_start_idx + vector_idx) % (0xff - data_chunks);
    } else
        fec_chunk_id = rand.randrange(FEC_CHUNK_COUNT_MAX - data_chunks);
    size_t chunk_id = fec_chunk_id + data_chunks;

    if (overwrite && (fec_chunks->second[vector_idx] == chunk_id))
        return true;

    if (CHUNK_COUNT_USES_CM256(data_chunks)) {
        cm256_encoder_params params { (int)data_chunks, uint8_t(256 - data_chunks - 1), FEC_CHUNK_SIZE };
        cm256_encode_block(params, cm256_blocks, chunk_id, &fec_chunks->first[vector_idx]);
    } else {
        uint32_t chunk_bytes;
        const WirehairResult encode_res = wirehair_encode(wirehair_encoder, chunk_id, &fec_chunks->first[vector_idx], FEC_CHUNK_SIZE, &chunk_bytes);
        if (encode_res != Wirehair_Success) {
            LogPrintf("wirehair_encode failed: %s\n", wirehair_result_string(encode_res));
            return false;
        }

        if (chunk_bytes != FEC_CHUNK_SIZE)
            memset(((char*)&fec_chunks->first[vector_idx]) + chunk_bytes, 0, FEC_CHUNK_SIZE - chunk_bytes);
    }

    fec_chunks->second[vector_idx] = chunk_id;
    return true;
}

bool FECEncoder::PrefillChunks() {
    bool fSuccess = true;
    for (size_t i = 0; i < fec_chunks->second.size() && fSuccess; i++) {
        fSuccess = BuildChunk(i);
    }
    return fSuccess;
}

bool BuildFECChunks(const std::vector<unsigned char>& data, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>& fec_chunks) {
    FECEncoder enc(&data, &fec_chunks);
    return enc.PrefillChunks();
}

class FECInit
{
public:
    FECInit() {
        assert(!wirehair_init());
        assert(!cm256_init());
        for (size_t i = 0; i < CACHE_STATES_COUNT; i++) {
            cache_states[i] = wirehair_decoder_create(nullptr, MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR, FEC_CHUNK_SIZE);
        }
    }
} instance_of_fecinit;
