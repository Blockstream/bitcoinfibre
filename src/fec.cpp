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

#define CHUNK_COUNT_USES_CM256(chunks) ((chunks) <= CM256_MAX_CHUNKS)

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

struct map_storage
{
    map_storage(boost::filesystem::path const& p, int const c) :
        chunk_count(c)
    {
        chunk_file = ::open(p.c_str(), O_RDWR, 0755);
        if (chunk_file == -1) {
            throw std::runtime_error("failed to open file: "
                + p.string() + " " + ::strerror(errno));
        }

        chunk_storage = static_cast<char*>(::mmap(nullptr, FEC_CHUNK_SIZE * chunk_count,
            PROT_READ | PROT_WRITE, MAP_SHARED, chunk_file, 0));
        if (chunk_storage == MAP_FAILED) {
            ::close(chunk_file);
            throw std::runtime_error("mmap failed " + p.string()
                + " " + ::strerror(errno));
        }
    }

    map_storage(map_storage&& ms) noexcept :
        chunk_count(ms.chunk_count),
        chunk_file(exchange(ms.chunk_file, -1)),
        chunk_storage(exchange(ms.chunk_storage, nullptr))
    {}

    ~map_storage()
    {
      if (chunk_storage != nullptr)
          ::munmap(chunk_storage, FEC_CHUNK_SIZE * chunk_count);
      if (chunk_file != -1)
          ::close(chunk_file);
    }

    char* storage() const { return chunk_storage; }

private:
    int chunk_count;
    int chunk_file = -1;
    char* chunk_storage = nullptr;
};

}

FECDecoder::FECDecoder() :
        filename(compute_filename())
{
}

FECDecoder::FECDecoder(size_t const data_size) :
        chunk_count(DIV_CEIL(data_size, FEC_CHUNK_SIZE)),
        obj_size(data_size),
        chunk_tracker(chunk_count),
        filename(compute_filename())
{
    if (chunk_count < 2)
        return;

    filename = compute_filename();
    boost::system::error_code ignore;
    fs::create_directories(filename.parent_path(), ignore);
    int const chunk_file = ::open(filename.c_str(), O_RDWR | O_CREAT, 0755);
    if (chunk_file == -1) {
        throw std::runtime_error("failed to open file: "
            + filename.string() + " " + ::strerror(errno));
    }
    int const ret = ::ftruncate(chunk_file, FEC_CHUNK_SIZE * chunk_count);
    if (ret != 0) {
        ::close(chunk_file);
        ::unlink(filename.c_str());
        throw std::runtime_error("ftruncate failed " + filename.string()
            + " " + ::strerror(errno));
    }
    ::close(chunk_file);
    owns_file = true;

    chunk_ids.reserve(chunk_count);
}

fs::path FECDecoder::compute_filename() const
{
    return GetDataDir() / "partial_blocks" / std::to_string(std::uintptr_t(this));
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
    cm256_map         = std::move(decoder.cm256_map);
    chunk_ids         = std::move(decoder.chunk_ids);
    if (owns_file) {
        fs::rename(decoder.filename, filename);
    }
    cm256_decoded    = exchange(decoder.cm256_decoded, false);
    tmp_chunk        = decoder.tmp_chunk;
    wirehair_decoder = exchange(decoder.wirehair_decoder, nullptr);
    return *this;
}

void FECDecoder::remove_file()
{
    map_storage s(filename, chunk_count);
    ::madvise(s.storage(), FEC_CHUNK_SIZE * chunk_count, MADV_REMOVE);
    ::unlink(filename.c_str());
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
    } else {
        map_storage s(filename, chunk_count);
        char* chunk_storage = s.storage();

        // both wirehair and cm256 need chunk_count chunks, so regardless of
        // which decoder we use, fill our chunk storage
        if (chunks_recvd < chunk_count) {
            auto const dest_ptr = chunk_storage + (chunks_recvd * FEC_CHUNK_SIZE);
            memcpy(dest_ptr, chunk, FEC_CHUNK_SIZE);
            chunk_ids.push_back(chunk_id);
        }
        if (CHUNK_COUNT_USES_CM256(chunk_count)) {
            if (chunk_count == chunks_recvd + 1)
                decodeComplete = true;
        } else {
            if (chunks_recvd + 1 == chunk_count) {
                // This was the "last" chunk. Now try to decode them!
                // this will potentially pull chunks back in from disk
                wirehair_decoder = wirehair_decoder_create(get_wirehair_codec(), obj_size, FEC_CHUNK_SIZE);
                assert(wirehair_decoder);
                assert(chunk_ids.size() == chunk_count);
                for (size_t i = 0; i < chunk_count; ++i) {
                    const WirehairResult decode_res = wirehair_decode(wirehair_decoder
                        , chunk_ids[i], chunk_storage + i * FEC_CHUNK_SIZE, FEC_CHUNK_SIZE);
                    if (decode_res == Wirehair_Success) {
                        decodeComplete = true;
                        break;
                    }
                    else if (decode_res != Wirehair_NeedMore) {
                        LogPrintf("wirehair_decode failed: %s\n", wirehair_result_string(decode_res));
                    }
                }
            }
            else if (chunks_recvd >= chunk_count) {
                // if we've received chunk_count chunks already, we will have
                // tried to decode. If we get here it means we failed to decode,
                // but we've already put everything in RAM, so we might as well
                // continue trying to decode as we go now. No need to use
                // chunk_storage
                assert(wirehair_decoder);
                const WirehairResult decode_res = wirehair_decode(wirehair_decoder
                    , chunk_id, (void*)chunk, FEC_CHUNK_SIZE);
                if (decode_res == Wirehair_Success) {
                    decodeComplete = true;
                }
                else if (decode_res != Wirehair_NeedMore) {
                    LogPrintf("wirehair_decode failed: %s\n", wirehair_result_string(decode_res));
                }
            }
        }
    }
    ++chunks_recvd;

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

const void* FECDecoder::GetDataPtr(uint32_t chunk_id) {
    assert(DecodeReady());
    assert(chunk_id < chunk_count);
    if (chunk_count >= 2) {
        if (CHUNK_COUNT_USES_CM256(chunk_count)) {
            map_storage s(filename, chunk_count);
            char* chunk_storage = s.storage();
            if (!cm256_decoded) {
                assert(chunk_ids.size() == chunk_count);
                assert(chunk_count <= CM256_MAX_CHUNKS);
                assert(chunk_id <= CM256_MAX_CHUNKS);

                // Fill in cm256 chunks in the order they were received. These
                // can consist of both original and recovery chunks.
                cm256_block cm256_blocks[CM256_MAX_CHUNKS];
                for (size_t i = 0; i < chunk_count; ++i) {
                    cm256_blocks[i].Block = chunk_storage + (FEC_CHUNK_SIZE * i);
                    cm256_blocks[i].Index = (uint8_t)chunk_ids[i];
                }

                cm256_encoder_params params { (int)chunk_count, (256 - (int)chunk_count - 1), FEC_CHUNK_SIZE };
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
                cm256_decoded = true;
            }
            assert(chunk_id < cm256_map.size());
            assert(cm256_map[chunk_id] < chunk_count);
            memcpy(&tmp_chunk, chunk_storage + cm256_map[chunk_id] * FEC_CHUNK_SIZE, FEC_CHUNK_SIZE);
        } else {
            uint32_t chunk_size = FEC_CHUNK_SIZE;
            assert(!wirehair_recover_block(wirehair_decoder, chunk_id, (void*)&tmp_chunk, &chunk_size));
        }
    }
    return &tmp_chunk;
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
