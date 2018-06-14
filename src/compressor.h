// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPRESSOR_H
#define BITCOIN_COMPRESSOR_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <hash.h>
#include <array>
#include <boost/variant.hpp>

using valtype = std::vector<unsigned char>;
using stattype = Span<uint64_t>;

enum class scriptSigTemplate : uint8_t {
    P2SH_P2WSH_OTHER,
    WIT_OTHER,
    NONWIT_OTHER,
    P2SH_UW,
    P2PK,
    P2PKH,
    P2WPKH,
    P2SH_P2WPKH,
    P2SH_P2WSH_P2PKH,
    MS,
    P2SH_MS,
    P2WSH_MS,
    P2SH_P2WSH_MS
};

const std::array<char const*, 13> scriptSigTemplateNames = {
    "P2SH_P2WSH_OTHER",
    "WIT_OTHER",
    "NONWIT_OTHER",
    "P2SH_UW",
    "P2PK",
    "P2PKH",
    "P2WPKH",
    "P2SH_P2WPKH",
    "P2SH_P2WSH_P2PKH",
    "MS",
    "P2SH_MS",
    "P2WSH_MS",
    "P2SH_P2WSH_MS"
};

class CKeyID;
class CPubKey;
class CScriptID;

bool CompressScript(const CScript& script, std::vector<unsigned char> &out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript& script, unsigned int nSize, const std::vector<unsigned char> &out);

uint64_t CompressAmount(uint64_t nAmount);
uint64_t DecompressAmount(uint64_t nAmount);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
class CScriptCompressor
{
private:
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new nVersion for
     * transactions, in which case this value becomes dependent on nVersion
     * and nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    CScript &script;
public:
    explicit CScriptCompressor(CScript &scriptIn) : script(scriptIn) { }

    template<typename Stream>
    void Serialize(Stream &s) const {
        std::vector<unsigned char> compr;
        if (CompressScript(script, compr)) {
            s << MakeSpan(compr);
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << MakeSpan(script);
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            std::vector<unsigned char> vch(GetSpecialScriptSize(nSize), 0x00);
            s >> MakeSpan(vch);
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> MakeSpan(script);
        }
    }
};

/** wrapper for CTxOut that provides a more compact serialization */
class CTxOutCompressor
{
private:
    CTxOut &txout;

public:
    explicit CTxOutCompressor(CTxOut &txoutIn) : txout(txoutIn) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (!ser_action.ForRead()) {
            uint64_t nVal = CompressAmount(txout.nValue);
            READWRITE(VARINT(nVal));
        } else {
            uint64_t nVal = 0;
            READWRITE(VARINT(nVal));
            txout.nValue = DecompressAmount(nVal);
        }
        CScriptCompressor cscript(REF(txout.scriptPubKey));
        READWRITE(cscript);
    }
};

enum class LockTimeCode : uint8_t { zero, varint, raw };

enum class SequenceCode : uint8_t { zero, final_seq, final_less_one, last_encoded, raw};

std::pair<LockTimeCode, uint8_t> ParseTxHeader(uint8_t TxHeader);
uint8_t GenerateTxHeader(uint32_t const lock_time, int32_t const version);

std::tuple<bool, uint8_t, SequenceCode> ParseTxInHeader(uint8_t TxInHeader);
uint8_t GenerateTxInHeader(bool last, CTxIn const& in, std::vector<uint32_t>& SequenceCache);

std::tuple<bool, uint8_t> ParseTxOutHeader(uint8_t TxOutHeader);
std::pair<uint8_t, valtype> GenerateTxOutHeader(bool last, CScript const& TxOutScriptPubKey);

bool IsFromScriptHashWitnessScriptHashOther(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsValidPubKey(valtype const& pubkey);
bool IsFromScriptHashWitnessScriptHash(Span<valtype const> stack, Span<valtype const> witnessstack);
bool IsFromMultisig(Span<valtype const> stack, stattype statistic);
bool IsFromEmbeddedMultisig(Span<valtype const> stack, stattype statistic);
bool IsFromPubKey(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromWitnessPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashWitnessPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromRawMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromWitnessScriptHashMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashWitnessScriptHashMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromScriptHashWitnessScriptHashPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromNonWitnessOther(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool IsFromWitnessOther(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic);
bool ValidSignatureEncoding(const std::vector<unsigned char> &sig);

std::pair<bool, std::vector<valtype>> encode_push_only(const CScript &scriptSig);
bool IsToPubKeyHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToScriptHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToWitnessPubKeyHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToWitnessScriptHash(CScript const& scriptPubKey, valtype& smallscript);
bool IsToPubKey(CScript const& scriptPubKey, valtype& smallscript);
bool IsToWitnessUnknown(CScript const& scriptPubKey, valtype& smallscript);

// copies the right part of src into the right part of dst
void right_align(Span<uint8_t const> src, Span<uint8_t> dst);

std::pair<uint8_t, valtype> StripSigPubKey(Span<valtype const> stack, bool sighashall);
valtype StripSig(const valtype &sig, bool sighashall);
valtype StripAllSigs(Span<valtype const> stack, bool sighashall);
valtype StripPubKey(const valtype &pubkey);
void StripAllPubKeys(Span<valtype const> stack, valtype &strippedpubkeys);
uint16_t KNCoder(uint64_t k, uint64_t n);
std::pair<uint16_t, valtype> GenerateScriptSigHeader(size_t txinindex, CTxIn const& in);
std::pair<scriptSigTemplate, uint16_t> ParseScriptSigHeader(uint16_t ScriptSigHeader, uint16_t lastCode);
scriptSigTemplate AnalyzeScriptSig(size_t txinindex, CTxIn const& in, stattype statistic);

CScript decode_push_only(Span<valtype const> values);
valtype PadHash(Span<unsigned char const> h, bool iswitnesshash);
valtype PadSig(Span<unsigned char const> strippedsig, bool sighashall);
valtype PadPubKey(Span<unsigned char const> strippedpubkey, uint16_t TemplateCode);
std::vector<valtype> PadSingleKeyStack(Span<unsigned char const> strippedstack
    , uint16_t TemplateCode, scriptSigTemplate TemplateType, const bool sighashall);
std::vector<valtype> PadMultisig(valtype strippedstack, scriptSigTemplate templateType, uint16_t TemplateCode);
std::pair<uint8_t, uint8_t> KNDecoder(uint16_t kncode);
void PadAllPubkeys(valtype &strippedstack, std::vector<valtype>& paddedstack, uint8_t n);
void PadScriptPubKey(uint8_t TxOutCode, CScript &scriptPubKey);

template <typename Stream>
void decompressTransaction(Stream& s, CMutableTransaction& tx);

template <typename Stream>
void compressTransaction(Stream& s, CTransaction const& tx);

/* Non-consensus wrapper for transactions that provides a more compact serialization */
class CTxCompressor
{
    boost::variant<CMutableTransaction*, CTransaction const*> tx;

public:
    explicit CTxCompressor(CTransactionRef const& txin) : tx(txin.get()) {}
    explicit CTxCompressor(CTransaction const& txin) : tx(&txin) {}
    explicit CTxCompressor(CMutableTransaction &txin) : tx(&txin) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        if (ser_action.ForRead()) {
            decompressTransaction(s, *boost::get<CMutableTransaction*>(tx));
        }
        else {
            compressTransaction(s, *boost::get<CTransaction const*>(tx));
        }
    }
};

#endif // BITCOIN_COMPRESSOR_H
