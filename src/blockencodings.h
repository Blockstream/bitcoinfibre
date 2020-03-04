// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKENCODINGS_H
#define BITCOIN_BLOCKENCODINGS_H

#include <fec.h> // For consumers - defines FEC_CHUNK_SIZE
#include <primitives/block.h>
#include <compressor.h>


class CTxMemPool;

// Transaction compression schemes for compact block relay can be introduced by writing
// an actual formatter here.
using TransactionCompression = DefaultFormatter;

class DifferenceFormatter
{
    uint64_t m_shift = 0;

public:
    template<typename Stream, typename I>
    void Ser(Stream& s, I v)
    {
        if (v < m_shift || v >= std::numeric_limits<uint64_t>::max()) throw std::ios_base::failure("differential value overflow");
        WriteCompactSize(s, v - m_shift);
        m_shift = uint64_t(v) + 1;
    }
    template<typename Stream, typename I>
    void Unser(Stream& s, I& v)
    {
        uint64_t n = ReadCompactSize(s);
        m_shift += n;
        if (m_shift < n || m_shift >= std::numeric_limits<uint64_t>::max() || m_shift < std::numeric_limits<I>::min() || m_shift > std::numeric_limits<I>::max()) throw std::ios_base::failure("differential value overflow");
        v = I(m_shift++);
    }
};

class BlockTransactionsRequest {
public:
    // A BlockTransactionsRequest message
    uint256 blockhash;
    std::vector<uint16_t> indexes;

    SERIALIZE_METHODS(BlockTransactionsRequest, obj)
    {
        READWRITE(obj.blockhash, Using<VectorFormatter<DifferenceFormatter>>(obj.indexes));
    }
};

class BlockTransactions {
public:
    // A BlockTransactions message
    uint256 blockhash;
    std::vector<CTransactionRef> txn;

    BlockTransactions() {}
    explicit BlockTransactions(const BlockTransactionsRequest& req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    SERIALIZE_METHODS(BlockTransactions, obj)
    {
        READWRITE(obj.blockhash, Using<VectorFormatter<TransactionCompression>>(obj.txn));
    }
};

// Dumb serialization/storage-helper for CBlockHeaderAndShortTxIDs and PartiallyDownloadedBlock
struct PrefilledTransaction {
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in PartiallyDownloadedBlock
    uint16_t index;
    CTransactionRef tx;

    SERIALIZE_METHODS(PrefilledTransaction, obj) { READWRITE(COMPACTSIZE(obj.index), Using<TransactionCompression>(obj.tx)); }
};

typedef enum ReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
    READ_STATUS_CHECKBLOCK_FAILED, // Used only by FillBlock to indicate a
                                   // failure in CheckBlock.
} ReadStatus;

class CBlockHeaderAndShortTxIDs {
private:
    mutable uint64_t shorttxidk0, shorttxidk1;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class PartiallyDownloadedBlock;

protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    static constexpr int SHORTTXIDS_LENGTH = 6;

    CBlockHeader header;

    // Dummy for deserialization
    CBlockHeaderAndShortTxIDs() {}

    CBlockHeaderAndShortTxIDs(const CBlock& block, bool fUseWTXID, bool fDeterministic = false);

    uint64_t GetShortID(const uint256& txhash) const;

    size_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs, obj)
    {
        READWRITE(obj.header, obj.nonce, Using<VectorFormatter<CustomUintFormatter<SHORTTXIDS_LENGTH>>>(obj.shorttxids), obj.prefilledtxn);
        if (ser_action.ForRead()) {
            if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) {
                throw std::ios_base::failure("indexes overflowed 16 bits");
            }
            obj.FillShortTxIDSelector();
        }
    }
};

class PartiallyDownloadedBlock {
protected:
    std::vector<CTransactionRef> txn_available;
    size_t prefilled_count = 0, mempool_count = 0, extra_count = 0;
    const CTxMemPool* pool;
public:
    CBlockHeader header;
    explicit PartiallyDownloadedBlock(CTxMemPool* poolIn) : pool(poolIn) {}

    // extra_txn is a list of extra transactions to look at, in <witness hash, reference> form
    ReadStatus InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn);
    bool IsTxAvailable(size_t index) const;
    ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing);
};


// FEC-Supporting extensions

class CBlockHeaderAndLengthShortTxIDs : public CBlockHeaderAndShortTxIDs {
private:
    codec_version_t codec_version; // Compression/decompression scheme's version
    std::vector<uint32_t> txlens; // compressed size by CTxCompressor
    // NOTE: the prefilled transactions from the base class are not compressed
    // since that would require an out-of-band channel to communicate
    // compression version down to the base class. Note that
    // CBlockHeadersAnsShortTxIDs is used in the normal bitcoin peer protocol as
    // well, where transactions are not compressed.
    friend class PartiallyDownloadedChunkBlock;
    int height = -1; // Block height - for OOOB storage of pre-BIP34 blocks
public:

    codec_version_t codec_ver() const { return codec_version; }

    CBlockHeaderAndLengthShortTxIDs(const CBlock& block, codec_version_t const cv,
        bool fDeterministic = false);

    // Dummy for deserialization
    CBlockHeaderAndLengthShortTxIDs() {}

    void setBlockHeight(int h) { height = h; }
    size_t ShortTxIdCount() const { return shorttxids.size(); }

    // Fills a map from offset within a FEC-coded block to the tx index in the block
    // Returns false if this object is invalid (txlens.size() != shortxids.size())
    template<typename F>
    ReadStatus FillIndexOffsetMap(F& callback) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*reinterpret_cast<std::uint8_t*>(&codec_version));
        READWRITE(height);

        READWRITE(*(CBlockHeaderAndShortTxIDs*)this);
        if (ser_action.ForRead()) {
            txlens.clear();
            txlens.reserve(shorttxids.size());
            for (size_t i = 0; i < shorttxids.size(); i++) {
                uint32_t len;
                READWRITE(VARINT(len));
                txlens.emplace_back(len);
            }
        } else {
            for (size_t i = 0; i < txlens.size(); i++)
                READWRITE(VARINT(txlens[i]));
        }
    }
};

// Valid options for the SIZE_FACTOR are 1 or 2, see cpp for more info
#define MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR 1

class ChunkCodedBlock {
private:
    std::vector<unsigned char> codedBlock;
public:
    ChunkCodedBlock(const CBlock& block, const CBlockHeaderAndLengthShortTxIDs& headerAndIDs);
    // Note that the coded block may be empty (ie prefilled txn in the header was full)
    const std::vector<unsigned char>& GetCodedBlock() const { return codedBlock; }
};

class VectorOutputStream;
class PartiallyDownloadedChunkBlock : private PartiallyDownloadedBlock {
private:
    std::map<size_t, size_t> index_offsets; // offset -> txindex
    std::vector<unsigned char> codedBlock;
    std::vector<bool> chunksAvailable;
    uint32_t remainingChunks;
    bool allTxnFromMempool;
    bool block_finalized = false;
    std::shared_ptr<CBlock> decoded_block;

    // this is initialized to what we read off the network in InitData()
    codec_version_t codec_version = codec_version_t::default_version;
    int height = -1; // either -1 or the block height advertised by the peer

    // Things used in the iterative fill-from-mempool:
    std::map<size_t, size_t>::iterator fill_coding_index_offsets_it;
    std::map<uint16_t, uint16_t> txn_prefilled; // index -> number of prefilled txn at or below index
    bool haveChunk = true;

    mutable uint256 block_hash; // Cached because its called in critical-path by udpnet

    bool SerializeTransaction(VectorOutputStream& stream, std::map<size_t, size_t>::iterator it);
public:
    PartiallyDownloadedChunkBlock(CTxMemPool* poolIn) : PartiallyDownloadedBlock(poolIn), decoded_block(std::make_shared<CBlock>()) {}

    // extra_txn is a list of extra transactions to look at, in <witness hash, reference> form
    ReadStatus InitData(const CBlockHeaderAndLengthShortTxIDs& comprblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn);
    ReadStatus DoIterativeFill(size_t& firstChunkProcessed);
    bool IsIterativeFillDone() const;

    bool IsBlockAvailable() const;
    bool IsHeaderNull() const;
    ReadStatus FinalizeBlock();
    std::shared_ptr<const CBlock> GetBlock() const { assert(block_finalized); return decoded_block; }
    const std::vector<unsigned char>& GetCodedBlock() const { assert(AreChunksAvailable() && IsBlockAvailable()); return codedBlock; }
    uint256& GetBlockHash() const;

    // Chunk-based methods are only callable if AreChunksAvailable()
    bool AreChunksAvailable() const;
    size_t GetChunkCount() const;
    bool IsChunkAvailable(size_t chunk) const;

    // To provide a chunk, write it to GetChunk and call MarkChunkAvailable
    // The unavailable chunk pointer must be written to before GetBlock,
    // but can happen after MarkChunkAvailable
    unsigned char* GetChunk(size_t chunk);
    void MarkChunkAvailable(size_t chunk);

    int getBlockHeight() { return height; }
};

#endif // BITCOIN_BLOCKENCODINGS_H
