// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2018-2019 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compressor.h>

#include <streams.h>
#include <hash.h>
#include <pubkey.h>
#include <script/standard.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <util/strencodings.h>

#include <iostream>

/*
 * These check for scripts for which a special case with a shorter encoding is defined.
 * They are implemented separately from the CScript test, as these test for exact byte
 * sequence correspondences, and are more strict. For example, IsToPubKey also verifies
 * whether the public key is valid (as invalid ones cannot be represented in compressed
 * form).
 */

static bool IsToKeyID(const CScript& script, CKeyID &hash)
{
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160
                            && script[2] == 20 && script[23] == OP_EQUALVERIFY
                            && script[24] == OP_CHECKSIG) {
        memcpy(&hash, &script[3], 20);
        return true;
    }
    return false;
}

static bool IsToScriptID(const CScript& script, CScriptID &hash)
{
    if (script.size() == 23 && script[0] == OP_HASH160 && script[1] == 20
                            && script[22] == OP_EQUAL) {
        memcpy(&hash, &script[2], 20);
        return true;
    }
    return false;
}

static bool IsToPubKey(const CScript& script, CPubKey &pubkey)
{
    if (script.size() == 35 && script[0] == 33 && script[34] == OP_CHECKSIG
                            && (script[1] == 0x02 || script[1] == 0x03)) {
        pubkey.Set(&script[1], &script[34]);
        return true;
    }
    if (script.size() == 67 && script[0] == 65 && script[66] == OP_CHECKSIG
                            && script[1] == 0x04) {
        pubkey.Set(&script[1], &script[66]);
        return pubkey.IsFullyValid(); // if not fully valid, a case that would not be compressible
    }
    return false;
}

bool CompressScript(const CScript& script, CompressedScript& out)
{
    CKeyID keyID;
    if (IsToKeyID(script, keyID)) {
        out.resize(21);
        out[0] = 0x00;
        memcpy(&out[1], &keyID, 20);
        return true;
    }
    CScriptID scriptID;
    if (IsToScriptID(script, scriptID)) {
        out.resize(21);
        out[0] = 0x01;
        memcpy(&out[1], &scriptID, 20);
        return true;
    }
    CPubKey pubkey;
    if (IsToPubKey(script, pubkey)) {
        out.resize(33);
        memcpy(&out[1], &pubkey[1], 32);
        if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
            out[0] = pubkey[0];
            return true;
        } else if (pubkey[0] == 0x04) {
            out[0] = 0x04 | (pubkey[64] & 0x01);
            return true;
        }
    }
    return false;
}

unsigned int GetSpecialScriptSize(unsigned int nSize)
{
    if (nSize == 0 || nSize == 1)
        return 20;
    if (nSize == 2 || nSize == 3 || nSize == 4 || nSize == 5)
        return 32;
    return 0;
}

bool DecompressScript(CScript& script, unsigned int nSize, const CompressedScript& in)
{
    switch(nSize) {
    case 0x00:
        script.resize(25);
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 20;
        memcpy(&script[3], in.data(), 20);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
        return true;
    case 0x01:
        script.resize(23);
        script[0] = OP_HASH160;
        script[1] = 20;
        memcpy(&script[2], in.data(), 20);
        script[22] = OP_EQUAL;
        return true;
    case 0x02:
    case 0x03:
        script.resize(35);
        script[0] = 33;
        script[1] = nSize;
        memcpy(&script[2], in.data(), 32);
        script[34] = OP_CHECKSIG;
        return true;
    case 0x04:
    case 0x05:
        unsigned char vch[33] = {};
        vch[0] = nSize - 2;
        memcpy(&vch[1], in.data(), 32);
        CPubKey pubkey{vch};
        if (!pubkey.Decompress())
            return false;
        assert(pubkey.size() == 65);
        script.resize(67);
        script[0] = 65;
        memcpy(&script[1], pubkey.begin(), 65);
        script[66] = OP_CHECKSIG;
        return true;
    }
    return false;
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10 possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d, and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])

uint64_t CompressAmount(uint64_t n)
{
    if (n == 0)
        return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (n % 10);
        assert(d >= 1 && d <= 9);
        n /= 10;
        return 1 + (n*9 + d - 1)*10 + e;
    } else {
        return 1 + (n - 1)*10 + 9;
    }
}

uint64_t DecompressAmount(uint64_t x)
{
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if (x == 0)
        return 0;
    x--;
    // x = 10*(9*n + d - 1) + e
    int e = x % 10;
    x /= 10;
    uint64_t n = 0;
    if (e < 9) {
        // x = 9*n + d - 1
        int d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x*10 + d;
    } else {
        n = x+1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return n;
}

std::pair<LockTimeCode, uint8_t> ParseTxHeader(uint8_t const TxHeader)
{
    return { LockTimeCode(TxHeader % 3), TxHeader / 3};
}

int32_t const nVersionThreshold = 15;
uint32_t const PrevOutThreshold = 23;
int const PrevOutVarInt = 24;
int const SequenceMultiplier = 50;

template <typename Stream>
void decompressTransaction(Stream& s, CMutableTransaction& tx)
{
    uint8_t TxHeader = 0;
    s >> TxHeader;
    LockTimeCode lock_time_code;
    uint8_t tx_version_code;
    std::tie(lock_time_code, tx_version_code) = ParseTxHeader(TxHeader);

    switch (lock_time_code) {
        case LockTimeCode::zero: tx.nLockTime = 0; break;
        case LockTimeCode::varint: s >> VARINT(tx.nLockTime); break;
        case LockTimeCode::raw: s >> tx.nLockTime; break;
    }

    if (tx_version_code > nVersionThreshold) {
        throw std::runtime_error("invalid compressed transaction. version greater than threshold");
    } else if (tx_version_code == nVersionThreshold) {
        s >> tx.nVersion;
    } else {
        tx.nVersion = tx_version_code;
    }

    // this is the last tempalte code we parsed out, in case a ScriptSigHeader
    // refers back to the last one
    uint16_t lastCode = 0;
    std::vector<uint32_t> SequenceCache;
    bool IsFinal = false;
    while (!IsFinal) {
        uint8_t TxPartHeader;
        s >> TxPartHeader;
        uint8_t PrevOutCode;
        SequenceCode SeqCode;
        std::tie(IsFinal, PrevOutCode, SeqCode) = ParseTxInHeader(TxPartHeader);
        tx.vin.push_back(CTxIn());
        CTxIn& txin = tx.vin.back();

        txin.prevout.SetNull();
        if (PrevOutCode != PrevOutThreshold) {
            uint32_t PrevOutPoint = 0;
            if (PrevOutCode < PrevOutThreshold) {
                PrevOutPoint = PrevOutCode;
            } else {
                s >> VARINT(PrevOutPoint);
            }
            uint256 PrevOutHash;
            s >> PrevOutHash;
            txin.prevout.n = PrevOutPoint;
            txin.prevout.hash = PrevOutHash;
        }

        switch (SeqCode) {
            case SequenceCode::zero: txin.nSequence = 0; break;
            case SequenceCode::final_seq: txin.nSequence = CTxIn::SEQUENCE_FINAL; break;
            case SequenceCode::final_less_one: txin.nSequence = CTxIn::SEQUENCE_FINAL - 1; break;
            case SequenceCode::last_encoded:
                if (SequenceCache.empty()) txin.nSequence = UINT32_MAX - 2;
                else txin.nSequence = SequenceCache.back();
                break;
            case SequenceCode::raw:
                s >> txin.nSequence;
                SequenceCache.push_back(txin.nSequence);
                break;
        }

        uint16_t ScriptSigHeader;
        s >> VARINT(ScriptSigHeader);
        scriptSigTemplate TemplateType;
        uint16_t TemplateCode;
        std::tie(TemplateType, TemplateCode) = ParseScriptSigHeader(ScriptSigHeader, lastCode);

        bool const sighashall = (TemplateCode % 2 == 0);
        txin.scriptSig.clear();
        txin.scriptWitness.SetNull();
        lastCode = TemplateCode;

        bool iswitnesshash = true;

        switch (TemplateType) {
        case scriptSigTemplate::P2SH_P2WSH_OTHER:
        case scriptSigTemplate::WIT_OTHER:
            s >> txin.scriptWitness.stack;
            if (TemplateType == scriptSigTemplate::P2SH_P2WSH_OTHER) {
                if (txin.scriptWitness.stack.empty()) {
                    throw std::runtime_error("invalid compressed transaction. empty scriptwitness stack");
                }
                std::vector<valtype> const scriptsigstack{ PadHash(MakeSpan(txin.scriptWitness.stack.back()), iswitnesshash) };
                txin.scriptSig = decode_push_only(MakeSpan(scriptsigstack));
            }
            break;
        case scriptSigTemplate::NONWIT_OTHER:
            s >> txin.scriptSig;
            break;
        case scriptSigTemplate::P2SH_UW:
            s >> txin.scriptSig;
            s >> txin.scriptWitness.stack;
            break;
        case scriptSigTemplate::P2PK: {
            valtype SmallScriptSig;
            s >> SmallScriptSig;
            std::vector<valtype> scriptsigstack { PadSig(MakeSpan(SmallScriptSig), TemplateCode % 2 == 0) };
            txin.scriptSig = decode_push_only(MakeSpan(scriptsigstack));
            break;
        }
        case scriptSigTemplate::P2PKH: {
            valtype SmallScriptSig;
            s >> SmallScriptSig;
            std::vector<valtype> scriptsigstack = PadSingleKeyStack(MakeSpan(SmallScriptSig),
                TemplateCode / 2, TemplateType, sighashall);
            txin.scriptSig = decode_push_only(MakeSpan(scriptsigstack));
            break;
        }
        case scriptSigTemplate::P2WPKH:
        case scriptSigTemplate::P2SH_P2WPKH:
        case scriptSigTemplate::P2SH_P2WSH_P2PKH: {
            valtype SmallScriptSig;
            s >> SmallScriptSig;
            std::vector<valtype> scriptsigstack = PadSingleKeyStack(MakeSpan(SmallScriptSig),
                TemplateCode / 2, TemplateType, sighashall);

            valtype temp;
            if (TemplateType == scriptSigTemplate::P2SH_P2WSH_P2PKH) {
                if (scriptsigstack.empty()) {
                    throw std::runtime_error("invalid compressed transaction. empty TxIn scriptsigstack");
                }
                auto const temp = scriptsigstack.back();
                scriptsigstack.pop_back();
                txin.scriptWitness.stack = scriptsigstack;
                scriptsigstack.clear();
                scriptsigstack.push_back(temp);
                txin.scriptSig = decode_push_only(MakeSpan(scriptsigstack));
            }
            else if (TemplateType == scriptSigTemplate::P2SH_P2WPKH) {
                if (scriptsigstack.empty()) {
                    throw std::runtime_error("invalid compressed transaction. empty TxIn scriptsigstack");
                }
                scriptsigstack.pop_back();
                txin.scriptWitness.stack = scriptsigstack;
                CScript const h = GetScriptForDestination(WitnessV0KeyHash(CPubKey(scriptsigstack[1]).GetID()));
                scriptsigstack.clear();
                scriptsigstack.push_back(valtype(h.begin(), h.end()));
                txin.scriptSig = decode_push_only(MakeSpan(scriptsigstack));
            }
            else {
                txin.scriptWitness.stack = scriptsigstack;
            }
            break;
        }
        case scriptSigTemplate::MS:
        case scriptSigTemplate::P2SH_MS:
        case scriptSigTemplate::P2WSH_MS:
        case scriptSigTemplate::P2SH_P2WSH_MS: {
            valtype SmallScriptSig;
            s >> SmallScriptSig;
            std::vector<valtype> scriptsigstack = PadMultisig(SmallScriptSig, TemplateType, TemplateCode);
            if (TemplateType == scriptSigTemplate::MS
                || TemplateType == scriptSigTemplate::P2SH_MS) {
                txin.scriptSig = decode_push_only(MakeSpan(scriptsigstack));
            } else {
                txin.scriptWitness.stack = scriptsigstack;
                if (TemplateType == scriptSigTemplate::P2SH_P2WSH_MS) {
                    if (txin.scriptWitness.stack.empty()) {
                        throw std::runtime_error("invalid compressed transaction. empty scriptwitness stack");
                    }
                    scriptsigstack.push_back(PadHash(MakeSpan(txin.scriptWitness.stack.back()), iswitnesshash));
                    txin.scriptSig = decode_push_only(MakeSpan(scriptsigstack));
                }
            }
            break;
        }
        }
    }

    IsFinal = false;

    while (!IsFinal) {
        uint8_t TxPartHeader;
        s >> TxPartHeader;
        uint8_t TxOutCode = 0;
        std::tie(IsFinal, TxOutCode) = ParseTxOutHeader(TxPartHeader);
        tx.vout.push_back(CTxOut());
        CTxOut& txout = tx.vout.back();

        if (TxOutCode == 100) {
            uint64_t scriptlength;
            s >> VARINT(scriptlength);
            txout.scriptPubKey.resize(scriptlength + 76);
        } else if (TxOutCode >= 24) {
            txout.scriptPubKey.resize(TxOutCode - 24);
        } else if (TxOutCode >= 8) {
            uint8_t scriptlength;
            s >> scriptlength;
            txout.scriptPubKey.resize(scriptlength);
        } else if (TxOutCode >= 3) {
            txout.scriptPubKey.resize(32);
        } else {
            txout.scriptPubKey.resize(20);
        }

        s >> MakeSpan(txout.scriptPubKey);

        if (TxOutCode < 24)
            PadScriptPubKey(TxOutCode, txout.scriptPubKey);

        uint64_t amount;
        s >> VARINT(amount);
        txout.nValue = DecompressAmount(amount);
    }
}

template <typename Stream>
void compressTransaction(Stream& s, CTransaction const& tx)
{
    uint8_t const TxHeader = GenerateTxHeader(tx.nLockTime, tx.nVersion);

    s << TxHeader;
    LockTimeCode lock_time_code;
    uint8_t tx_version_code;
    std::tie(lock_time_code, tx_version_code) = ParseTxHeader(TxHeader);

    switch (lock_time_code) {
        case LockTimeCode::varint: s << VARINT(tx.nLockTime); break;
        case LockTimeCode::raw: s << tx.nLockTime; break;
        default: break; // nothing to do. time code is 0
    }

    if (tx_version_code == nVersionThreshold) {
        s << tx.nVersion;
    }

    bool IsFinal = false;
    std::vector<uint32_t> SequenceCache;

    for (size_t i = 0; i < tx.vin.size(); i++) {
        uint8_t const TxPartHeader = GenerateTxInHeader(i + 1 == tx.vin.size(), tx.vin[i], SequenceCache);

        s << TxPartHeader;

        uint8_t PrevOutCode;
        SequenceCode SeqCode;
        std::tie(IsFinal, PrevOutCode, SeqCode) = ParseTxInHeader(TxPartHeader);

        if (PrevOutCode != PrevOutThreshold) {
            if (PrevOutCode == PrevOutVarInt) {
                s << VARINT(tx.vin[i].prevout.n);
            }
            s << tx.vin[i].prevout.hash;
        }

        if (SeqCode == SequenceCode::raw) {
            s << tx.vin[i].nSequence;
        }

        uint16_t ScriptSigHeader;
        valtype SmallScriptSig;
        std::tie(ScriptSigHeader, SmallScriptSig) = GenerateScriptSigHeader(i, tx.vin[i]);

        s << VARINT(ScriptSigHeader);
        if (ScriptSigHeader < 4) {
            if (ScriptSigHeader < 2) {
                s << tx.vin[i].scriptWitness.stack;
            } else if (ScriptSigHeader == 2) {
                s << tx.vin[i].scriptSig;
            } else {
                s << tx.vin[i].scriptSig;
                s << tx.vin[i].scriptWitness.stack;
            }
        } else {
            s << SmallScriptSig;
        }
    }

    for (size_t i = 0; i < tx.vout.size(); i++) {
        bool const last = i + 1 == tx.vout.size();
        valtype txoutscriptdata;
        uint8_t TxPartHeader;
        std::tie(TxPartHeader, txoutscriptdata) = GenerateTxOutHeader(last, tx.vout[i].scriptPubKey);

        s << TxPartHeader;
        uint8_t TxOutCode = 0;
        std::tie(IsFinal, TxOutCode) = ParseTxOutHeader(TxPartHeader);

        if (TxOutCode == 100) {
            s << VARINT((uint64_t)txoutscriptdata.size()-76);
        } else if (TxOutCode >= 8 && TxOutCode < 24) {
            s << (uint8_t)txoutscriptdata.size();
        }

        s << MakeSpan(txoutscriptdata);
        uint64_t const amount = CompressAmount(tx.vout[i].nValue);
        s << VARINT(amount);
    }
}

template void compressTransaction<CDataStream>(CDataStream&, CTransaction const&);
template void compressTransaction<VectorOutputStream>(VectorOutputStream&, CTransaction const&);
template void compressTransaction<CVectorWriter>(CVectorWriter&, CTransaction const&);
template void compressTransaction<CSizeComputer>(CSizeComputer&, CTransaction const&);
template void decompressTransaction<CDataStream>(CDataStream&, CMutableTransaction&);
template void decompressTransaction<VectorInputStream>(VectorInputStream&, CMutableTransaction&);

uint8_t GenerateTxHeader(uint32_t const lock_time, uint32_t const version)
{
    uint32_t const VarIntThreshold = 2113663;

    uint8_t const tx_header = (lock_time > VarIntThreshold) ? 2
        : (lock_time != 0) ? 1 : 0;

    if (version < nVersionThreshold) {
        return tx_header + 3 * version;
    }
    else {
        return tx_header + 3 * nVersionThreshold;
    };
}

uint8_t GenerateTxInHeader(bool const last, CTxIn const& in, std::vector<uint32_t>& SequenceCache)
{
    uint8_t TxInHeader = 0;

    // last-bit
    if (last) {
        TxInHeader++;
    }

    // prev-out code
    if (in.prevout.n < PrevOutThreshold) {
        // explicitly encode prev-out in the header
        TxInHeader+=2*in.prevout.n;
    } else if (in.prevout.hash.IsNull() && in.prevout.n == UINT32_MAX) {
        // special case for coinbase prev-out
        TxInHeader+=2*PrevOutThreshold;
    } else {
        // fall back to encoding using varint
        TxInHeader+=2*PrevOutVarInt;
    }

    if (in.nSequence == CTxIn::SEQUENCE_FINAL) {
        TxInHeader+=1*SequenceMultiplier;
    } else if (in.nSequence == UINT32_MAX-1) {
        TxInHeader+=2*SequenceMultiplier;
    } else if (SequenceCache.size() != 0 && in.nSequence == SequenceCache.back()) {
        TxInHeader+=3*SequenceMultiplier;
    } else if (SequenceCache.size() == 0 && in.nSequence == UINT32_MAX-2) {
        TxInHeader+=3*SequenceMultiplier;
    } else if (in.nSequence > 0) {
        TxInHeader+=4*SequenceMultiplier;
        SequenceCache.push_back(in.nSequence);
    }
    return TxInHeader;
}

std::tuple<bool, uint8_t, SequenceCode> ParseTxInHeader(uint8_t TxInHeader)
{
    bool const isfinal = TxInHeader & 1;
    TxInHeader >>= 1;
    if (TxInHeader / 25 > 4) throw std::runtime_error("invalid sequence code in TxInHeader");
    return { isfinal, TxInHeader % 25, SequenceCode(TxInHeader / 25) };
}

// This function verifies that a script only pushes data onto the stack. If so,
// it returns true as well as the resulting stack (sort of). OP_1NEGATE is
// allowed and considered "push-only" and is encoded as a value of 0x81.
// a push-only script that does not use the optimal encoding is also rejected,
// e.g. using <1> { 1 } instead of OP_1.
// the typical scriptSig only pushes data, so it's expected to be common
std::pair<bool, std::vector<valtype>> encode_push_only(const CScript &scriptSig)
{
    if (scriptSig.empty()) return {false, {}};

    std::vector<valtype> ret;
    CScript::const_iterator pc = scriptSig.begin();
    while (pc < scriptSig.end()) {
        opcodetype opcode;
        valtype data;
        if (!scriptSig.GetOp(pc, opcode, data)) return {false, ret};
        auto const sz = data.size();
        if (opcode == OP_1NEGATE) {
            data.assign(1, 0x81);
        } else if (opcode >= OP_1 && opcode <= OP_16) {
            data.assign(1, opcode - OP_1 + 1);
        } else {
            if (opcode < OP_0 || opcode > OP_PUSHDATA4) return {false, ret};
            if (sz == 0 && opcode != OP_0) return {false, ret};
            if (sz == 1) {
                if (data[0] >= 1 && data[0] <= 16 && opcode != (OP_1 + data[0] - 1)) return {false, ret};
                if (data[0] == 0x81 && opcode != OP_1NEGATE) return {false, ret};
            }
            if (sz > 1 && sz <= 75 && opcode != sz) return {false, ret};
            if (sz > 75 && sz <= 255 && opcode != OP_PUSHDATA1) return {false, ret};
            if (sz > 255 && sz <= 65535 && opcode != OP_PUSHDATA2) return {false, ret};
            if (sz > 65535 && opcode != OP_PUSHDATA4) return {false, ret};
        }
        ret.emplace_back(std::move(data));
    }

    return {true, ret};
}
/*
bool ValidSignatureEncoding(const std::vector<unsigned char> &sig)
{
    if (sig.size() < 9 || sig.size() > 73) return false;
    if (sig[0] != 0x30 || sig[1] != sig.size() - 3) return false;
    unsigned int lenR = sig[3];
    if (5 + lenR >= sig.size()) return false;
    unsigned int lenS = sig[5 + lenR];
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;
    if (sig[2] != 0x02 || lenR == 0 || (sig[4] & 0x80)) return false;
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;
    if (sig[lenR + 4] != 0x02 || lenS == 0 || (sig[lenR + 6] & 0x80)) return false;
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;
    return true;
}
*/
bool IsValidPubKey(const valtype &pubkey)
{
    CPubKey pk(pubkey);
    // 0x06 and 0x07 are "hybrid encodings" for keys
    // virtually all keys are fully valid, but we can only turn them into the
    // compressed format if they are
    return pk.IsFullyValid() && pk[0] != 0x06 && pk[0] != 0x07;
}

bool IsFromScriptHashWitnessScriptHash(Span<valtype const> stack, Span<valtype const> witnessstack)
{
    if (stack.size() == 1 && stack[0].size() == 34 && stack[0][0] == 0 && stack[0][1] == 32 && witnessstack.size() > 1) {
        unsigned char witnessscripthash[32];
        CSHA256().Write(witnessstack.back().data(), witnessstack.back().size()).Finalize(witnessscripthash);
        if (memcmp(witnessscripthash, &stack[0][2], 32) == 0) return true;
    }
    return false;
}

bool IsFromMultisig(Span<valtype const> stack, stattype statistic)
{
    if (stack.size() < 2 || stack[0].size() != 0) return false;
    for (auto const& s : stack) {
        if (!IsValidSignatureEncoding(s)) return false;
        if (s.back() != SIGHASH_ALL) statistic[0]++;
    }
    statistic[1]++;
    statistic[2] += (stack.size() - 1);
    return true;
}

bool IsFromEmbeddedMultisig(Span<valtype const> stack, stattype statistic)
{
    if (stack.size() < 3 || stack[0].size() != 0) return false;
    valtype redeemscript = std::move(stack.back());
    // pop the last element
    Span<valtype const> solostack(stack.data(), stack.size() - 1);
    if (redeemscript.size() < 1 || redeemscript.back() != OP_CHECKMULTISIG) return false;
    redeemscript.pop_back();
    std::array<uint64_t, 3> multisigcache = {0, 0, 0};
    if (IsFromMultisig(solostack, MakeSpan(multisigcache))) {
        unsigned int const sigcount = (solostack.size() - 1);

        std::vector<valtype> redeemstack;
        bool push_only;
        std::tie(push_only, redeemstack) = encode_push_only(CScript(redeemscript.begin(), redeemscript.end()));
        if (!push_only) return false;
        if (redeemstack.size() < 3 || redeemstack[0].size() != 1 || redeemstack.back().size() != 1) return false;
        unsigned int const pkcount = redeemstack.size() - 2;
        if (redeemstack[0][0] != sigcount || redeemstack.back()[0] != pkcount) return false;
        uint64_t compressedcount = 0;
        for (size_t i = 1; i < (pkcount + 1); ++i) {
            if (!IsValidPubKey(redeemstack[i])) return false;
            if (redeemstack[i].size() == 33) compressedcount++;
        }
        if (sigcount > 20 || pkcount > 21) return false;
        for (uint8_t i = 0; i < 3; ++i) {
            statistic[i] += multisigcache[i];
        }
        statistic[3] += pkcount;
        statistic[4] += compressedcount;
        return true;
    }
    return false;
}

bool IsFromPubKey(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (witnessstack.size() == 0 && stack.size() == 1 && IsValidSignatureEncoding(stack[0])) {
        if (stack[0].back() != SIGHASH_ALL) statistic[0]++;
        statistic[1]++;
        return true;
    }
    return false;
}

bool IsFromPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (witnessstack.size() == 0 && stack.size() == 2 && IsValidSignatureEncoding(stack[0]) && IsValidPubKey(stack[1])) {
        if (stack[0].back() != SIGHASH_ALL) statistic[0]++;
        statistic[1]++;
        if (stack[1].size() != 33) statistic[2]++;
        return true;
    }
    return false;
}

bool IsFromWitnessPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (stack.size() == 0 && witnessstack.size() == 2 && IsValidSignatureEncoding(witnessstack[0]) && IsValidPubKey(witnessstack[1])) {
        if (witnessstack[0].back() != SIGHASH_ALL) statistic[0]++;
        statistic[1]++;
        if (witnessstack[1].size() != 33) statistic[2]++;
        return true;
    }
    return false;
}

bool IsFromScriptHashWitnessPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (stack.size() == 1 && witnessstack.size() == 2 && IsValidSignatureEncoding(witnessstack[0]) && IsValidPubKey(witnessstack[1])) {
        CScript const witnessscripthash = GetScriptForDestination(WitnessV0KeyHash(CPubKey(witnessstack[1]).GetID()));
        if (witnessscripthash == CScript(stack[0].begin(), stack[0].end())) {
            if (witnessstack[0].back() != SIGHASH_ALL) statistic[0]++;
            statistic[1]++;
            if (witnessstack[1].size() != 33) statistic[2]++;
            return true;
        }
    }
    return false;
}

bool IsFromRawMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (witnessstack.size() == 0 && IsFromMultisig(stack, statistic)) return true;
    return false;
}

bool IsFromScriptHashMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (witnessstack.size() == 0 && IsFromEmbeddedMultisig(stack, statistic)) return true;
    return false;
}

bool IsFromWitnessScriptHashMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (stack.size() == 0 && IsFromEmbeddedMultisig(witnessstack, statistic)) return true;
    return false;
}

bool IsFromScriptHashWitnessScriptHashMultisig(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (IsFromScriptHashWitnessScriptHash(stack, witnessstack) && IsFromEmbeddedMultisig(witnessstack, statistic)) return true;
    return false;
}

bool IsFromScriptHashWitnessScriptHashPubKeyHash(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (IsFromScriptHashWitnessScriptHash(stack, witnessstack) && witnessstack.size() == 3) {
        unsigned char newpubkeyhash[20];
        CHash160().Write(witnessstack[1]).Finalize(newpubkeyhash);
        valtype oldpubkeyhash;
        CScript const pubkeyhash (witnessstack[2].begin(), witnessstack[2].end());
        if (IsToPubKeyHash(pubkeyhash, oldpubkeyhash) && (memcmp(newpubkeyhash, &oldpubkeyhash[0], 20) == 0)) {
            assert(oldpubkeyhash.size() == 20);
            if (witnessstack[0].back() != SIGHASH_ALL) statistic[0]++;
            statistic[1]++;
            if (witnessstack[1].size() != 33) statistic[2]++;
            return true;
        }
    }
    return false;
}

bool IsFromScriptHashWitnessScriptHashOther(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (IsFromScriptHashWitnessScriptHash(stack, witnessstack)) {
        statistic[0] += witnessstack.size();
        statistic[1]++;
        return true;
    }
    return false;
}

bool IsFromNonWitnessOther(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (witnessstack.size() == 0) {
        statistic[0] += stack.size();
        statistic[1]++;
        return true;
    }
    return false;
}

bool IsFromWitnessOther(Span<valtype const> stack, Span<valtype const> witnessstack, stattype statistic)
{
    if (stack.size() == 0) {
        statistic[0] += witnessstack.size();
        statistic[1]++;
        return true;
    }
    return false;
}

// turn uncompressed pubkeys into compressed ones
scriptSigTemplate AnalyzeScriptSig(size_t const txinindex, CTxIn const& in, stattype statistic)
{
    using t = scriptSigTemplate;
    std::vector<valtype> witnessstack;
    if (!in.scriptWitness.IsNull())
        witnessstack = in.scriptWitness.stack;
    Span<valtype const> witness(witnessstack.data(), witnessstack.size());
    std::vector<valtype> stack;
    bool push_only;
    std::tie(push_only, stack) = encode_push_only(in.scriptSig);

    if (push_only) {
        if (IsFromPubKeyHash(MakeSpan(stack), witness, statistic)) return t::P2PKH;
        else if (IsFromScriptHashMultisig(MakeSpan(stack), witness, statistic)) return t::P2SH_MS;
        else if (IsFromScriptHashWitnessPubKeyHash(MakeSpan(stack), witness, statistic)) return t::P2SH_P2WPKH;
        else if (IsFromScriptHashWitnessScriptHashMultisig(MakeSpan(stack), witness, statistic)) return t::P2SH_P2WSH_MS;
        else if (IsFromWitnessPubKeyHash(MakeSpan(stack), witness, statistic)) return t::P2WPKH;
        else if (IsFromPubKey(MakeSpan(stack), witness, statistic)) return t::P2PK;
        else if (IsFromWitnessScriptHashMultisig(MakeSpan(stack), witness, statistic)) return t::P2WSH_MS;
        else if (IsFromRawMultisig(MakeSpan(stack), witness, statistic)) return t::MS;
        else if (IsFromScriptHashWitnessScriptHashPubKeyHash(MakeSpan(stack), witness, statistic)) return t::P2SH_P2WSH_P2PKH;
        else if (IsFromScriptHashWitnessScriptHashOther(MakeSpan(stack), witness, statistic)) return t::P2SH_P2WSH_OTHER;
    }
    if (IsFromNonWitnessOther(MakeSpan(stack), witness, statistic)) return t::NONWIT_OTHER;
    else if (IsFromWitnessOther(MakeSpan(stack), witness, statistic)) return t::WIT_OTHER;
    else {
        statistic[0] += witness.size();
        statistic[1]++;
        return t::P2SH_UW;
    }
}

// copies src into the right side of dst
void right_align(Span<uint8_t const> src, Span<uint8_t> dst)
{
    if (src.size() > dst.size()) src = src.subspan(src.size() - dst.size());
    else if (dst.size() > src.size()) dst = dst.subspan(dst.size() - src.size());
    std::copy(src.begin(), src.end(), dst.begin());
}

// signatures on chain are encoded with DER encoding. 8 bytes overhead
// This function decodes the signature and outputs a fixed 64 bytes plain encoding
// 32 bytes for R and 32 bytes for S
// https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L97L118
valtype StripSig(const valtype &sig, bool const sighashall)
{
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    assert(IsValidSignatureEncoding(sig));

    valtype ret(64);

    const std::ptrdiff_t r_len = sig[3];
    // if r_len > 32, it means it has a leading 0 (to avoid interpreting the value as negative)
    // if r_len < 32, it means it's a smaller value, we need to pad it with leading zeroes

    std::ptrdiff_t offset = 4;
    right_align(Span<const uint8_t>(sig.data() + offset, r_len), MakeSpan(ret).subspan(0, 32));

    offset += r_len + 1;
    const std::ptrdiff_t s_len = sig[offset];
    offset += 1;

    right_align(Span<const uint8_t>(sig.data() + offset, s_len), MakeSpan(ret).subspan(32, 32));
    if (!sighashall) {
        assert((long int) sig.size() == offset + s_len + 1);
        ret.push_back(sig.back());
    }
     else {
         // the sighashall flag tells us that we already know what this flag is,
         // so we can avoid including it
         assert(sig.back() == SIGHASH_ALL);
     }

    return ret;
}

// Given an uncompressed public key, returns the compressed version
valtype StripPubKey(const valtype &pubkey)
{
    valtype ret;

    if (pubkey.size() == 65 && (pubkey.back() & 0x01)) {
        ret.assign(pubkey.begin(), pubkey.begin()+33);
        --ret[0];
    }
    else {
        ret = pubkey;
        ret[0] -= 0x02;
    }
    return ret;
}

std::pair<uint8_t, valtype> StripSigPubKey(Span<valtype const> stack, bool const sighashall)
{
    assert(stack.size() > 1);
    valtype retval = StripSig(stack[0], sighashall);
    valtype strippedpubkey = StripPubKey(stack[1]);
    uint8_t ret = 0;
    if (!sighashall)
        ret++;
    ret += 2 * strippedpubkey[0];
    strippedpubkey.erase(strippedpubkey.begin());
    retval.insert(retval.end(), strippedpubkey.begin(), strippedpubkey.end());
    return { ret, retval };
}

valtype StripAllSigs(Span<valtype const> stack, bool const sighashall)
{
    valtype ret;
    for (valtype const& v : stack.subspan(1)) {
        valtype sigcache = StripSig(v, sighashall);
        ret.insert(ret.end(), sigcache.begin(), sigcache.end());
    }
    return ret;
}

valtype StripAllPubKeys(Span<valtype const> stack)
{
    std::array<uint8_t, 24> pubkeyprefixes;
    uint8_t prefixoffset = 0;
    if (stack.size() == 1) {
        prefixoffset++;
    } else {
        prefixoffset += (((stack.size() - 1) / 4) + 1);
    }
    valtype ret;
    ret.insert(ret.begin(), prefixoffset, 0x00);
    for (size_t i = 0; i < stack.size(); ++i) {
        valtype pubkeycache = StripPubKey(stack[i]);
        pubkeyprefixes[i] = pubkeycache[0];
        pubkeycache.erase(pubkeycache.begin());
        ret.insert(ret.end(), pubkeycache.begin(), pubkeycache.end());
    }
    for (int i = 0; i < prefixoffset; ++i) {
        uint8_t prefixcache = (pubkeyprefixes[4*i] << 6)
            | (pubkeyprefixes[4*i+1] << 4)
            | (pubkeyprefixes[4*i+2] << 2)
            | (pubkeyprefixes[4*i+3]);
        ret[i] = prefixcache;
    }
    return ret;
}

uint16_t KNCoder(uint64_t const k, uint64_t const n)
{
    if (k == 1) {
        if (n == 1 || n == 2)
            return k + n - 2;
    } else if (k == 2) {
        if (n == 2 || n == 3 || n == 4)
            return k + n - 2;
    } else if (k == 3) {
        if (n == 4 || n == 5)
            return k + n - 2;
    } else {
        uint16_t kncode = n * (n - 1);
        kncode /= 2;
        kncode += (k + 3);
        return kncode;
    }
    return 0;
}

std::pair<uint16_t, valtype> GenerateScriptSigHeader(size_t const txinindex, CTxIn const& in)
{
    uint16_t ScriptSigHeader = 0;
    valtype SmallScriptSig;

    std::array<uint64_t, 5> statistic = {0, 0, 0, 0, 0};
    std::vector<valtype> witnessstack;
    if (!in.scriptWitness.IsNull()) {
        witnessstack = in.scriptWitness.stack;
    }
    bool sighashall = true;
    scriptSigTemplate const templateType = AnalyzeScriptSig(txinindex, in, MakeSpan(statistic));
    if (statistic[0] != 0)
        sighashall = false;

    std::vector<valtype> const stack = encode_push_only(in.scriptSig).second;
    switch (templateType) {
    case scriptSigTemplate::P2SH_P2WSH_OTHER:
    case scriptSigTemplate::WIT_OTHER:
    case scriptSigTemplate::NONWIT_OTHER:
    case scriptSigTemplate::P2SH_UW:
        ScriptSigHeader += static_cast<uint8_t>(templateType);
        break;
    case scriptSigTemplate::P2PK:
        ScriptSigHeader += static_cast<uint8_t>(templateType);
        if (!sighashall)
            ScriptSigHeader++;
        SmallScriptSig = StripSig(stack[0], sighashall);
        break;

    case scriptSigTemplate::P2PKH:
    case scriptSigTemplate::P2WPKH:
    case scriptSigTemplate::P2SH_P2WPKH:
    case scriptSigTemplate::P2SH_P2WSH_P2PKH: {
        ScriptSigHeader += 6 + 8 * (static_cast<uint16_t>(templateType) - 5);
        if (templateType == scriptSigTemplate::P2PKH) {
            uint8_t head;
            valtype ret;
            std::tie(head, ret) = StripSigPubKey(MakeSpan(stack), sighashall);
            ScriptSigHeader += head;
            return { ScriptSigHeader, std::move(ret) };
        } else {
            uint8_t head;
            valtype ret;
            std::tie(head, ret) = StripSigPubKey(MakeSpan(witnessstack), sighashall);
            ScriptSigHeader += head;
            return { ScriptSigHeader, std::move(ret) };
        }
        break;
    }
    case scriptSigTemplate::MS:
        ScriptSigHeader += 38;
        ScriptSigHeader += (statistic[2] - 1);
        SmallScriptSig = StripAllSigs(MakeSpan(stack), sighashall);
        break;
    default:
        ScriptSigHeader += 38 + (static_cast<uint8_t>(templateType) - 9);
        if (!sighashall)
            ScriptSigHeader += 4;
        uint16_t const kncode = KNCoder(statistic[2], statistic[3]);
        ScriptSigHeader += 8 * kncode;
        std::vector<valtype> sigstack = witnessstack;
        if (templateType == scriptSigTemplate::P2SH_MS)
            sigstack = stack;
        std::vector<valtype> pkstack = encode_push_only(CScript(sigstack.back().begin(), sigstack.back().end())).second;
        sigstack.pop_back();
        pkstack.erase(pkstack.begin());
        pkstack.pop_back();
        SmallScriptSig = StripAllSigs(MakeSpan(sigstack), sighashall);
        valtype const strippedpubkeys = StripAllPubKeys(MakeSpan(pkstack));
        SmallScriptSig.insert(SmallScriptSig.end(), strippedpubkeys.begin(), strippedpubkeys.end());
        break;
    }
    return { ScriptSigHeader, std::move(SmallScriptSig) };
}

std::pair<scriptSigTemplate, uint16_t> ParseScriptSigHeader(uint16_t ScriptSigHeader, uint16_t lastCode)
{
    scriptSigTemplate TemplateType;
    uint16_t TemplateCode;
    if (ScriptSigHeader < 4) {
        TemplateType = static_cast<scriptSigTemplate>(ScriptSigHeader);
        TemplateCode = lastCode;
    } else if (ScriptSigHeader < 6) {
        TemplateType = scriptSigTemplate::P2PK;
        TemplateCode = ScriptSigHeader % 2;
    } else if (ScriptSigHeader < 38) {
        ScriptSigHeader -= 6;
        if (ScriptSigHeader == 0) {
            TemplateType = scriptSigTemplate::P2PKH;
        } else {
            TemplateType = static_cast<scriptSigTemplate>(static_cast<uint8_t>(scriptSigTemplate::P2PKH) + (ScriptSigHeader / 8));
        }
        TemplateCode = ScriptSigHeader % 8;
    } else {
        ScriptSigHeader -= 38;
        TemplateType = static_cast<scriptSigTemplate>(ScriptSigHeader % 4);
        TemplateCode = ScriptSigHeader / 4;
    }
    return { TemplateType, TemplateCode };
}

bool IsToPubKey(CScript const& scriptPubKey, valtype& smallscript)
{
    if (scriptPubKey.size() == 35 && scriptPubKey[0] == 33 && scriptPubKey[34] == OP_CHECKSIG && (scriptPubKey[1] == 0x02 || scriptPubKey[1] == 0x03)) {
        smallscript = valtype(scriptPubKey.begin()+1, scriptPubKey.begin()+34);
        return true;
    } else if (scriptPubKey.size() == 67 && scriptPubKey[0] == 65 && scriptPubKey[66] == OP_CHECKSIG && scriptPubKey[1] == 0x04) {
        valtype pubkey(&scriptPubKey[1], &scriptPubKey[66]);
        if (IsValidPubKey(pubkey)) {
            smallscript = valtype(scriptPubKey.begin()+1, scriptPubKey.begin()+34);
            if (pubkey[64] & 0x01)
                smallscript[0]++;
            return true;
        }
    }
    return false;
}

bool IsToPubKeyHash(CScript const& scriptPubKey, valtype& smallscript)
{
    if (scriptPubKey.size() == 25 && scriptPubKey[0] == OP_DUP && scriptPubKey[1] == OP_HASH160
        && scriptPubKey[2] == 20 && scriptPubKey[23] == OP_EQUALVERIFY && scriptPubKey[24] == OP_CHECKSIG) {
        smallscript = valtype(scriptPubKey.begin()+3, scriptPubKey.begin()+23);
        return true;
    }
    return false;
}

bool IsToScriptHash(CScript const& scriptPubKey, valtype& smallscript)
{
    if (scriptPubKey.size() == 23 && scriptPubKey[0] == OP_HASH160 && scriptPubKey[1] == 0x14 && scriptPubKey[22] == OP_EQUAL) {
        smallscript = valtype(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        return true;
    }
    return false;
}

bool IsToWitnessPubKeyHash(CScript const& scriptPubKey, valtype& smallscript)
{
    if (scriptPubKey.size() == 22 && scriptPubKey[0] == OP_0 && scriptPubKey[1] == 0x14) {
        smallscript = valtype(scriptPubKey.begin()+2, scriptPubKey.end());
        return true;
    }
    return false;
}

bool IsToWitnessScriptHash(CScript const& scriptPubKey, valtype& smallscript)
{
    if (scriptPubKey.size() == 34 && scriptPubKey[0] == OP_0 && scriptPubKey[1] == 0x20) {
        smallscript = valtype(scriptPubKey.begin()+2, scriptPubKey.end());
        return true;
    }
    return false;
}

bool IsToWitnessUnknown(CScript const& scriptPubKey, valtype& smallscript)
{
    if (scriptPubKey.size() < 4 || scriptPubKey.size() > 42) {
        return false;
    }
    if (scriptPubKey[0] < OP_1 || scriptPubKey[0] > OP_15) {
        return false;
    }
    if ((size_t)(scriptPubKey[1] + 2) == scriptPubKey.size()) {
        smallscript.insert(smallscript.begin(), scriptPubKey.begin(), scriptPubKey.end());
        return true;
    }
    return false;
}

std::pair<uint8_t, valtype> GenerateTxOutHeader(bool const last, CScript const& scriptPubKey)
{
    valtype compressOut;
    uint8_t TxOutHeader = 0;

    if (last)
        TxOutHeader++;

    if (IsToPubKeyHash(scriptPubKey, compressOut)) {
    } else if (IsToScriptHash(scriptPubKey, compressOut)) {
        TxOutHeader+=2;
    } else if (IsToWitnessPubKeyHash(scriptPubKey, compressOut)) {
        TxOutHeader+=4;
    } else if (IsToWitnessScriptHash(scriptPubKey, compressOut)) {
        TxOutHeader+=6;
    } else if (IsToPubKey(scriptPubKey, compressOut)) {
        TxOutHeader+=8;
        switch (compressOut[0])
        {
            case 0x02:
                break;
            case 0x03:
                TxOutHeader+=2;
                break;
            case 0x04:
                TxOutHeader+=4;
                break;
            case 0x05:
                TxOutHeader+=6;
                break;
        }
        compressOut.erase(compressOut.begin());
    } else if (IsToWitnessUnknown(scriptPubKey, compressOut)) {
        TxOutHeader+=(16 + 2*CScript::DecodeOP_N((opcodetype)compressOut[0]));
        compressOut.erase(compressOut.begin());
        compressOut.erase(compressOut.begin());
    } else {
        TxOutHeader+=48;
        if (scriptPubKey.size() < 76)
            TxOutHeader+=2*scriptPubKey.size();
        else
            TxOutHeader+=152;
        compressOut.insert(compressOut.end(), scriptPubKey.begin(), scriptPubKey.end());
    }
    return { TxOutHeader, compressOut };
}

std::tuple<bool, uint8_t> ParseTxOutHeader(uint8_t const TxOutHeader)
{
    bool const isfinal = (TxOutHeader & 1) == 1;
    return { isfinal, TxOutHeader >> 1 };
}

// This take the script output produced by encode_push_only(), and re-creates the
// original SCript.
CScript decode_push_only(Span<valtype const> values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

valtype PadHash(Span<unsigned char const> const h, bool const iswitnesshash)
{
    if (!iswitnesshash) {
        unsigned char hashcache[CRIPEMD160::OUTPUT_SIZE];
        CScript pubkeyhash(h.begin(), h.end());
        uint8_t scriptpubkeycode = 0;
        PadScriptPubKey(scriptpubkeycode, pubkeyhash);
        valtype temp(pubkeyhash.begin(), pubkeyhash.end());
        CHash160().Write(temp).Finalize(hashcache);
        valtype ret(22);
        ret[0] = 0x00;
        ret[1] = 20;
        memcpy(ret.data() + 2, hashcache, 20);
        return ret;
    } else {
        unsigned char hashcache[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(h.data(), h.size()).Finalize(hashcache);
        valtype ret(34);
        ret[0] = 0x00;
        ret[1] = 32;
        memcpy(ret.data() + 2, hashcache, 32);
        return ret;
    }
}

// trims leading zeroes from 'number'. If the most significant bit is set on
// the first non-zero byte, one leading zero is left in
Span<uint8_t const> ltrim(Span<uint8_t const> number)
{
    while (number.size() > 1
        && number[0] == 0
        && (number[1] & 0x80) == 0)
    {
        number = number.subspan(1);
    }
    return number;
}

valtype PadSig(Span<unsigned char const> const strippedsig, bool const sighashall)
{
    if ((strippedsig.size() != 64 && sighashall)
        || (strippedsig.size() != 65 && !sighashall))
    {
        throw std::runtime_error("invalid compressed transaction; signature has invalid size");
    }

    // the output format is:
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

    valtype ret;
    Span<uint8_t const> const r = ltrim(strippedsig.subspan(0, 32));
    Span<uint8_t const> const s = ltrim(strippedsig.subspan(32, 32));

    ret.push_back(0x30);
    ret.push_back(0); // this is a place-holder

    // add R value
    ret.push_back(0x02);
    bool const r_pad = (r.front() & 0x80);
    ret.push_back(r.size() + r_pad);
    if (r_pad) ret.push_back(0x00);
    ret.insert(ret.end(), r.begin(), r.end());

    // add S value
    ret.push_back(0x02);
    bool const s_pad = (s.front() & 0x80);
    ret.push_back(s.size() + s_pad);
    if (s_pad) ret.push_back(0x00);
    ret.insert(ret.end(), s.begin(), s.end());

    // patch up the length field, now that we know how long it ended up being
    ret[1] = ret.size() - 2;

    ret.push_back(sighashall ? uint8_t(SIGHASH_ALL) : strippedsig.back());

    return ret;
}

valtype PadPubKey(Span<unsigned char const> const strippedpubkey, uint16_t const TemplateCode)
{
    valtype ret;
    ret.reserve(1 + strippedpubkey.size());
    if (TemplateCode >= 2) {
        ret.push_back(TemplateCode);
        ret.insert(ret.end(), strippedpubkey.begin(), strippedpubkey.end());
        assert(ret.size() >= 33);
        CPubKey pubkey(ret.data(), ret.data() + 33);
        pubkey.Decompress();
        ret.assign(pubkey.begin(), pubkey.begin() + 65);
    } else {
        ret.push_back(TemplateCode + 2);
        ret.insert(ret.end(), strippedpubkey.begin(), strippedpubkey.end());
    }
    return ret;
}

std::vector<valtype> PadSingleKeyStack(Span<unsigned char const> const strippedstack
    , uint16_t const TemplateCode, scriptSigTemplate const TemplateType, bool const sighashall)
{
    std::vector<valtype> ret(2);

    size_t const sig_length = 64 + (sighashall ? 0 : 1);
    if (strippedstack.size() < sig_length + 32) throw std::runtime_error("invalid compressed transaction");
    ret[0] = PadSig(strippedstack.subspan(0, sig_length), sighashall);
    ret[1] = PadPubKey(strippedstack.subspan(sig_length), TemplateCode);
    switch (TemplateType) {
        case scriptSigTemplate::P2SH_P2WPKH:
        case scriptSigTemplate::P2SH_P2WSH_P2PKH:
        case scriptSigTemplate::MS:
        case scriptSigTemplate::P2SH_MS:
        case scriptSigTemplate::P2WSH_MS:
        case scriptSigTemplate::P2SH_P2WSH_MS: {

        bool iswitnesshash = false;
        if (TemplateType == scriptSigTemplate::P2SH_P2WSH_P2PKH) {
            iswitnesshash = true;
            unsigned char h[20];
            CHash160().Write(ret[1]).Finalize(h);
            CScript pubkeyhash (std::begin(h), std::end(h));
            uint8_t scriptpubkeycode = 0;
            PadScriptPubKey(scriptpubkeycode, pubkeyhash);
            ret.resize(2);
            ret.emplace_back(pubkeyhash.begin(), pubkeyhash.end());
        }
        ret.push_back(PadHash(MakeSpan(ret.back()), iswitnesshash));
        break;
    }
    default: break;
    }

    return ret;
}

std::pair<uint8_t, uint8_t> KNDecoder(uint16_t kncode)
{
    if (kncode <= 6) {
        if (kncode <= 1) {
            return { 1, kncode + 1 };
        } else if (kncode <= 4) {
            return { 2, kncode };
        } else {
            return { 3, kncode - 1 };
        }
    }
    kncode -= 3;
    uint8_t k = 0;
    uint8_t n = 3;
    uint8_t knrow = 1;
    knrow += (n * (n - 1));
    while (n < 21 && k == 0) {
        if (kncode >= knrow + n) {
            knrow += n;
            n++;
        } else {
            k = 1 + kncode - knrow;
        }
    }
    return { k, n };
}

void PadAllPubkeys(valtype &strippedstack, std::vector<valtype>& paddedstack, uint8_t const n)
{
    if (strippedstack.size() < 32) {
        throw std::runtime_error("invalid compressed transaction; stripped stack too short");
    }
    int remainingkeys = n;
    uint8_t const prefixoffset = (n <= 4) ? 1 : ((n - 1) / 4) + 1;
    for (int i = 0; i < prefixoffset; ++i) {
        std::array<uint8_t, 4> pubkeyprefixes{};
        pubkeyprefixes[0] = (strippedstack[0] & 0xC0) >> 6;
        pubkeyprefixes[1] = (strippedstack[0] & 0x30) >> 4;
        pubkeyprefixes[2] = (strippedstack[0] & 0x0C) >> 2;
        pubkeyprefixes[3] = (strippedstack[0] & 0x03);
        strippedstack.erase(strippedstack.begin());
        uint8_t const groupsize = std::min(4, remainingkeys);
        for (int j = 0; j < groupsize; ++i, ++j) {
            valtype temp(strippedstack.begin(), strippedstack.begin() + 32);
            temp = PadPubKey(MakeSpan(temp), pubkeyprefixes[i]);
            paddedstack.push_back(temp);
            strippedstack.erase(strippedstack.begin(), strippedstack.begin()+32);
        }
        remainingkeys -= 4;
    }
}

std::vector<valtype> PadMultisig(valtype strippedstack, scriptSigTemplate const TemplateType
    , uint16_t const TemplateCode)
{
    uint8_t k = 0;
    uint8_t n = 0;
    uint16_t const sighashnotall = TemplateCode & 1;
    if (TemplateType == scriptSigTemplate::MS) {
        k = TemplateCode + 1;
    } else {
        std::tie(k, n) = KNDecoder(TemplateCode >> 1);
    }
    std::vector<valtype> ret(k + 1);
    ret[0] = valtype();
    uint8_t const offset = 64 + sighashnotall;
    for (int i = 0; i < k; ++i) {
        valtype tmp(strippedstack.begin(), strippedstack.begin()+offset);
        ret[i+1] = PadSig(MakeSpan(tmp), TemplateCode % 2 == 0);
        strippedstack.erase(strippedstack.begin(), strippedstack.begin()+offset);
    }
    if (TemplateType != scriptSigTemplate::MS) {
        CScript redeemscript;
        std::vector<valtype> redeemstack;
        redeemstack.push_back({k});
        PadAllPubkeys(strippedstack, redeemstack, n);
        redeemstack.push_back({n});
        redeemstack.push_back({OP_CHECKMULTISIG});
        redeemscript = decode_push_only(MakeSpan(redeemstack));
        ret.emplace_back(redeemscript.begin(), redeemscript.end());
    }
    return ret;
}

void PadScriptPubKey(uint8_t const TxOutCode, CScript &scriptPubKey)
{
    valtype fixcache;
    if (TxOutCode >= 8) {
        fixcache.push_back(CScript::EncodeOP_N(TxOutCode - 8));
        fixcache.push_back(scriptPubKey.size());
        scriptPubKey.insert(scriptPubKey.begin(), fixcache.begin(), fixcache.end());
    } else if (TxOutCode >= 4) {
        if ((TxOutCode - 4) >= 2) {
            scriptPubKey.insert(scriptPubKey.begin(), TxOutCode - 4);
            CPubKey pubkey(&scriptPubKey[0], &scriptPubKey[33]);
            pubkey.Decompress();
            scriptPubKey.resize(66);
            scriptPubKey[0] = 65;
            memcpy(&scriptPubKey[1], pubkey.begin(), 65);
        } else {
            fixcache.push_back(33);
            fixcache.push_back(TxOutCode - 2);
            scriptPubKey.insert(scriptPubKey.begin(), fixcache.begin(), fixcache.end());
        }
        scriptPubKey.push_back(OP_CHECKSIG);
    } else if (TxOutCode == 3) {
        fixcache.push_back(OP_0);
        fixcache.push_back(0x20);
        scriptPubKey.insert(scriptPubKey.begin(), fixcache.begin(), fixcache.end());
    } else if (TxOutCode == 2) {
        fixcache.push_back(OP_0);
        fixcache.push_back(0x14);
        scriptPubKey.insert(scriptPubKey.begin(), fixcache.begin(), fixcache.end());
    } else if (TxOutCode == 1) {
        fixcache.push_back(OP_HASH160);
        fixcache.push_back(0x14);
        scriptPubKey.insert(scriptPubKey.begin(), fixcache.begin(), fixcache.end());
        scriptPubKey.push_back(OP_EQUAL);
    } else {
        fixcache.push_back(OP_DUP);
        fixcache.push_back(OP_HASH160);
        fixcache.push_back(20);
        scriptPubKey.insert(scriptPubKey.begin(), fixcache.begin(), fixcache.end());
        scriptPubKey.push_back(OP_EQUALVERIFY);
        scriptPubKey.push_back(OP_CHECKSIG);
    }
}
