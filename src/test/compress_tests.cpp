// Copyright (c) 2012-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compressor.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <key_io.h>
#include <streams.h>
#include <util/system.h>
#include <util/strencodings.h>

#include <stdint.h>
#include <base58.h>

#include <boost/test/unit_test.hpp>
#include <sys/types.h>
#include <dirent.h>

// amounts 0.00000001 .. 0.00100000
#define NUM_MULTIPLES_UNIT 100000

// amounts 0.01 .. 100.00
#define NUM_MULTIPLES_CENT 10000

// amounts 1 .. 10000
#define NUM_MULTIPLES_1BTC 10000

// amounts 50 .. 21000000
#define NUM_MULTIPLES_50BTC 420000

BOOST_FIXTURE_TEST_SUITE(compress_tests, BasicTestingSetup)

bool static TestEncode(uint64_t in) {
    return in == DecompressAmount(CompressAmount(in));
}

bool static TestDecode(uint64_t in) {
    return in == CompressAmount(DecompressAmount(in));
}

bool static TestPair(uint64_t dec, uint64_t enc) {
    return CompressAmount(dec) == enc &&
           DecompressAmount(enc) == dec;
}

BOOST_AUTO_TEST_CASE(compress_amounts)
{
    BOOST_CHECK(TestPair(            0,       0x0));
    BOOST_CHECK(TestPair(            1,       0x1));
    BOOST_CHECK(TestPair(         CENT,       0x7));
    BOOST_CHECK(TestPair(         COIN,       0x9));
    BOOST_CHECK(TestPair(      50*COIN,      0x32));
    BOOST_CHECK(TestPair(21000000*COIN, 0x1406f40));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_UNIT; i++)
        BOOST_CHECK(TestEncode(i));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_CENT; i++)
        BOOST_CHECK(TestEncode(i * CENT));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_1BTC; i++)
        BOOST_CHECK(TestEncode(i * COIN));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_50BTC; i++)
        BOOST_CHECK(TestEncode(i * 50 * COIN));

    for (uint64_t i = 0; i < 100000; i++)
        BOOST_CHECK(TestDecode(i));
}

BOOST_AUTO_TEST_CASE(compress_script_to_ckey_id)
{
    // case CKeyID
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(script.size(), 25U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 21U);
    BOOST_CHECK_EQUAL(out[0], 0x00);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 3, 20), 0); // compare the 20 relevant chars of the CKeyId in the script
}

BOOST_AUTO_TEST_CASE(compress_script_to_cscript_id)
{
    // case CScriptID
    CScript script, redeemScript;
    script << OP_HASH160 << ToByteVector(CScriptID(redeemScript)) << OP_EQUAL;
    BOOST_CHECK_EQUAL(script.size(), 23U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 21U);
    BOOST_CHECK_EQUAL(out[0], 0x01);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 20), 0); // compare the 20 relevant chars of the CScriptId in the script
}

BOOST_AUTO_TEST_CASE(compress_script_to_compressed_pubkey_id)
{
    CKey key;
    key.MakeNewKey(true); // case compressed PubKeyID

    CScript script = CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG; // COMPRESSED_PUBLIC_KEY_SIZE (33)
    BOOST_CHECK_EQUAL(script.size(), 35U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 33U);
    BOOST_CHECK_EQUAL(memcmp(out.data(), script.data() + 1, 1), 0);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 32), 0); // compare the 32 chars of the compressed CPubKey
}

BOOST_AUTO_TEST_CASE(compress_script_to_uncompressed_pubkey_id)
{
    CKey key;
    key.MakeNewKey(false); // case uncompressed PubKeyID
    CScript script =  CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG; // PUBLIC_KEY_SIZE (65)
    BOOST_CHECK_EQUAL(script.size(), 67U);                   // 1 char code + 65 char pubkey + OP_CHECKSIG

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 33U);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 32), 0); // first 32 chars of CPubKey are copied into out[1:]
    BOOST_CHECK_EQUAL(out[0], 0x04 | (script[65] & 0x01)); // least significant bit (lsb) of last char of pubkey is mapped into out[0]
}

BOOST_AUTO_TEST_CASE(parse_tx_out_header)
{
    using ret = std::tuple<bool, uint8_t>;
    BOOST_CHECK(ParseTxOutHeader(0) == ret(false, 0));
    BOOST_CHECK(ParseTxOutHeader(1) == ret(true, 0));
    BOOST_CHECK(ParseTxOutHeader(2) == ret(false, 1));
    BOOST_CHECK(ParseTxOutHeader(3) == ret(true, 1));
    BOOST_CHECK(ParseTxOutHeader(1 + (42 << 1)) == ret(true, 42));
    BOOST_CHECK(ParseTxOutHeader(42 << 1) == ret(false, 42));
    BOOST_CHECK(ParseTxOutHeader(127 << 1) == ret(false, 127));
    BOOST_CHECK(ParseTxOutHeader(1 + (127 << 1)) == ret(true, 127));
}

BOOST_AUTO_TEST_CASE(parse_tx_header)
{
    using ret = std::pair<LockTimeCode, uint8_t>;
    BOOST_CHECK(ParseTxHeader(0) == ret(LockTimeCode::zero, 0));
    BOOST_CHECK(ParseTxHeader(1) == ret(LockTimeCode::varint, 0));
    BOOST_CHECK(ParseTxHeader(2) == ret(LockTimeCode::raw, 0));
    BOOST_CHECK(ParseTxHeader(7) == ret(LockTimeCode::varint, 2));

    BOOST_CHECK(ParseTxHeader(GenerateTxHeader(2113663, 0)) == ret(LockTimeCode::varint, 0));
    BOOST_CHECK(ParseTxHeader(GenerateTxHeader(2113663, 2)) == ret(LockTimeCode::varint, 2));
    BOOST_CHECK(ParseTxHeader(GenerateTxHeader(2113664, 2)) == ret(LockTimeCode::raw, 2));
    BOOST_CHECK(ParseTxHeader(GenerateTxHeader(1, 3)) == ret(LockTimeCode::varint, 3));
    BOOST_CHECK(ParseTxHeader(GenerateTxHeader(0, 3)) == ret(LockTimeCode::zero, 3));
}


BOOST_AUTO_TEST_CASE(generate_tx_header)
{
    // the lock-time code
    BOOST_CHECK(GenerateTxHeader(0, 0) == 0);
    BOOST_CHECK(GenerateTxHeader(1, 0) == 1);
    BOOST_CHECK(GenerateTxHeader(2, 0) == 1);
    BOOST_CHECK(GenerateTxHeader(2113663, 0) == 1);
    BOOST_CHECK(GenerateTxHeader(2113664, 0) == 2);
    BOOST_CHECK(GenerateTxHeader(2200000, 0) == 2);

    // version
    BOOST_CHECK(GenerateTxHeader(0, 1) == 3);
    BOOST_CHECK(GenerateTxHeader(0, 2) == 6);
    BOOST_CHECK(GenerateTxHeader(0, 3) == 9);

    // both
    BOOST_CHECK(GenerateTxHeader(1, 3) == 10);
    BOOST_CHECK(GenerateTxHeader(2, 3) == 10);
    BOOST_CHECK(GenerateTxHeader(2113663, 3) == 10);
    BOOST_CHECK(GenerateTxHeader(2113664, 3) == 11);

    // out-of-bound version
    BOOST_CHECK(GenerateTxHeader(1, 9999) == 1 + 3 * 15);
    BOOST_CHECK(GenerateTxHeader(1, -9999) == 1 + 3 * 15);
}

BOOST_AUTO_TEST_CASE(generate_tx_in_header)
{
    // last-bit
    {
    CTxIn txin;
    txin.prevout.n = 0;
    txin.scriptSig = CScript();
    txin.nSequence = 0;
    std::vector<uint32_t> cache;

    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 0);
    BOOST_CHECK(GenerateTxInHeader(true, txin, cache) == 1);
    }

    // prev-out
    {
    CTxIn txin;
    txin.prevout.n = 22;
    txin.scriptSig = CScript();
    txin.nSequence = 0;
    std::vector<uint32_t> cache;

    // small values of prev-out are encoded directly in the header
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 2 * 22);

    txin.prevout.n = 13;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 2 * 13);

    txin.prevout.n = 3;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 2 * 3);

    // coinbase prev-out is a special case
    txin.prevout.n = UINT32_MAX;
    txin.prevout.hash.SetNull();
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 2 * 23);

    // large prev-outs are encoded as varint
    txin.prevout.n = 1234;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 2 * 24);
    }

    // sequence
    {
    CTxIn txin;
    txin.prevout.n = 0;
    txin.scriptSig = CScript();
    txin.nSequence = 12345;
    std::vector<uint32_t> cache = {12345};

    // last encoded sequence
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 3 * 50);

    // with an empty cache, it represents 0xfffffffd
    cache.clear();
    txin.nSequence = CTxIn::SEQUENCE_FINAL - 2;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 3 * 50);

    txin.nSequence = CTxIn::SEQUENCE_FINAL;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 1 * 50);

    txin.nSequence = CTxIn::SEQUENCE_FINAL - 1;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 2 * 50);

    // any normal value is encoded as SequenceCode 4
    txin.nSequence = 12;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 4 * 50);

    txin.nSequence = 54321;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 4 * 50);

    // sequence number 0 is a special case
    txin.nSequence = 0;
    BOOST_CHECK(GenerateTxInHeader(false, txin, cache) == 0 * 50);
    }
}

bool invalid_seq(std::runtime_error const& ex)
{
    return ex.what() == std::string("invalid sequence code in TxInHeader");
}

BOOST_AUTO_TEST_CASE(parse_tx_in_header)
{
    using ret = std::tuple<bool, uint8_t, SequenceCode>;
    // last-bit
    BOOST_CHECK(ParseTxInHeader(0) == ret(false, 0, SequenceCode::zero));
    BOOST_CHECK(ParseTxInHeader(1) == ret(true, 0, SequenceCode::zero));

    // prev-out
    // small values
    BOOST_CHECK(ParseTxInHeader(2 * 22) == ret(false, 22, SequenceCode::zero));
    BOOST_CHECK(ParseTxInHeader(2 * 13) == ret(false, 13, SequenceCode::zero));
    BOOST_CHECK(ParseTxInHeader(2 * 5) == ret(false, 5, SequenceCode::zero));

    // coinbase
    BOOST_CHECK(ParseTxInHeader(2 * 23) == ret(false, 23, SequenceCode::zero));

    // varint
    BOOST_CHECK(ParseTxInHeader(2 * 24) == ret(false, 24, SequenceCode::zero));

    // sequence
    BOOST_CHECK(ParseTxInHeader(50 * 1) == ret(false, 0, SequenceCode::final_seq));
    BOOST_CHECK(ParseTxInHeader(50 * 2) == ret(false, 0, SequenceCode::final_less_one));
    BOOST_CHECK(ParseTxInHeader(50 * 3) == ret(false, 0, SequenceCode::last_encoded));
    BOOST_CHECK(ParseTxInHeader(50 * 4) == ret(false, 0, SequenceCode::raw));

    // this is a reserved sequence code
    BOOST_CHECK_EXCEPTION(ParseTxInHeader(50 * 5), std::runtime_error, invalid_seq);

    // combine
    BOOST_CHECK(ParseTxInHeader(1 + 2 * 23 + 50 * 3) == ret(true, 23, SequenceCode::last_encoded));
    BOOST_CHECK(ParseTxInHeader(1 + 2 * 24 + 50 * 3) == ret(true, 24, SequenceCode::last_encoded));
    BOOST_CHECK(ParseTxInHeader(1 + 2 * 4 + 50 * 2) == ret(true, 4, SequenceCode::final_less_one));
}

BOOST_AUTO_TEST_CASE(parse_scriptsig_header)
{
    using ret = std::pair<scriptSigTemplate, uint16_t>;

    // back-references to the previous code
    BOOST_CHECK(ParseScriptSigHeader(0, 42)  == ret(scriptSigTemplate::P2SH_P2WSH_OTHER, 42));
    BOOST_CHECK(ParseScriptSigHeader(1, 42)  == ret(scriptSigTemplate::WIT_OTHER, 42));
    BOOST_CHECK(ParseScriptSigHeader(2, 42)  == ret(scriptSigTemplate::NONWIT_OTHER, 42));
    BOOST_CHECK(ParseScriptSigHeader(3, 42)  == ret(scriptSigTemplate::P2SH_UW, 42));

    // previous code is ignored in these cases
    BOOST_CHECK(ParseScriptSigHeader(4, 42)  == ret(scriptSigTemplate::P2PK, 0));
    BOOST_CHECK(ParseScriptSigHeader(5, 42)  == ret(scriptSigTemplate::P2PK, 1));

    BOOST_CHECK(ParseScriptSigHeader(6, 42)  == ret(scriptSigTemplate::P2PKH, 0));
    BOOST_CHECK(ParseScriptSigHeader(7, 42)  == ret(scriptSigTemplate::P2PKH, 1));
    BOOST_CHECK(ParseScriptSigHeader(8, 42)  == ret(scriptSigTemplate::P2PKH, 2));
    BOOST_CHECK(ParseScriptSigHeader(9, 42)  == ret(scriptSigTemplate::P2PKH, 3));
    BOOST_CHECK(ParseScriptSigHeader(10, 42) == ret(scriptSigTemplate::P2PKH, 4));
    BOOST_CHECK(ParseScriptSigHeader(11, 42) == ret(scriptSigTemplate::P2PKH, 5));
    BOOST_CHECK(ParseScriptSigHeader(12, 42) == ret(scriptSigTemplate::P2PKH, 6));
    BOOST_CHECK(ParseScriptSigHeader(13, 42) == ret(scriptSigTemplate::P2PKH, 7));

    BOOST_CHECK(ParseScriptSigHeader(14, 42) == ret(scriptSigTemplate::P2WPKH, 0));
    BOOST_CHECK(ParseScriptSigHeader(15, 42) == ret(scriptSigTemplate::P2WPKH, 1));
    BOOST_CHECK(ParseScriptSigHeader(16, 42) == ret(scriptSigTemplate::P2WPKH, 2));
    BOOST_CHECK(ParseScriptSigHeader(17, 42) == ret(scriptSigTemplate::P2WPKH, 3));
    BOOST_CHECK(ParseScriptSigHeader(18, 42) == ret(scriptSigTemplate::P2WPKH, 4));
    BOOST_CHECK(ParseScriptSigHeader(19, 42) == ret(scriptSigTemplate::P2WPKH, 5));
    BOOST_CHECK(ParseScriptSigHeader(20, 42) == ret(scriptSigTemplate::P2WPKH, 6));
    BOOST_CHECK(ParseScriptSigHeader(21, 42) == ret(scriptSigTemplate::P2WPKH, 7));

    BOOST_CHECK(ParseScriptSigHeader(22, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 0));
    BOOST_CHECK(ParseScriptSigHeader(23, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 1));
    BOOST_CHECK(ParseScriptSigHeader(24, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 2));
    BOOST_CHECK(ParseScriptSigHeader(25, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 3));
    BOOST_CHECK(ParseScriptSigHeader(26, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 4));
    BOOST_CHECK(ParseScriptSigHeader(27, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 5));
    BOOST_CHECK(ParseScriptSigHeader(28, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 6));
    BOOST_CHECK(ParseScriptSigHeader(29, 42) == ret(scriptSigTemplate::P2SH_P2WPKH, 7));

    BOOST_CHECK(ParseScriptSigHeader(30, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 0));
    BOOST_CHECK(ParseScriptSigHeader(31, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 1));
    BOOST_CHECK(ParseScriptSigHeader(32, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 2));
    BOOST_CHECK(ParseScriptSigHeader(33, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 3));
    BOOST_CHECK(ParseScriptSigHeader(34, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 4));
    BOOST_CHECK(ParseScriptSigHeader(35, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 5));
    BOOST_CHECK(ParseScriptSigHeader(36, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 6));
    BOOST_CHECK(ParseScriptSigHeader(37, 42) == ret(scriptSigTemplate::P2SH_P2WSH_P2PKH, 7));

    BOOST_CHECK(ParseScriptSigHeader(38, 42) == ret(scriptSigTemplate::P2SH_P2WSH_OTHER, 0));
    BOOST_CHECK(ParseScriptSigHeader(39, 42) == ret(scriptSigTemplate::WIT_OTHER, 0));
    BOOST_CHECK(ParseScriptSigHeader(40, 42) == ret(scriptSigTemplate::NONWIT_OTHER, 0));
    BOOST_CHECK(ParseScriptSigHeader(41, 42) == ret(scriptSigTemplate::P2SH_UW, 0));

    BOOST_CHECK(ParseScriptSigHeader(42, 42) == ret(scriptSigTemplate::P2SH_P2WSH_OTHER, 1));
    BOOST_CHECK(ParseScriptSigHeader(43, 42) == ret(scriptSigTemplate::WIT_OTHER, 1));
    BOOST_CHECK(ParseScriptSigHeader(44, 42) == ret(scriptSigTemplate::NONWIT_OTHER, 1));
    BOOST_CHECK(ParseScriptSigHeader(45, 42) == ret(scriptSigTemplate::P2SH_UW, 1));

    BOOST_CHECK(ParseScriptSigHeader(46, 42) == ret(scriptSigTemplate::P2SH_P2WSH_OTHER, 2));
    BOOST_CHECK(ParseScriptSigHeader(47, 42) == ret(scriptSigTemplate::WIT_OTHER, 2));
    BOOST_CHECK(ParseScriptSigHeader(48, 42) == ret(scriptSigTemplate::NONWIT_OTHER, 2));
    BOOST_CHECK(ParseScriptSigHeader(49, 42) == ret(scriptSigTemplate::P2SH_UW, 2));
}

namespace {
bool round_trip_compress_transaction(CMutableTransaction& tx)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << CTxCompressor(CTransaction(tx), codec_version_t::v1);

    CMutableTransaction ret;
    stream >> CTxCompressor(ret, codec_version_t::v1);

    stream << tx;
    CSerializeData original;
    stream.GetAndClear(original);

    stream << ret;
    CSerializeData round_tripped;
    stream.GetAndClear(round_tripped);

    BOOST_CHECK(round_tripped == original);
    if (round_tripped != original) {
        printf("=== round-tripped:\nlen=%d\n%s\n\n=== original:\nlen=%d\n%s\n\n"
            , int(round_tripped.size()), CTransaction(ret).ToString().c_str()
            , int(original.size()), CTransaction(tx).ToString().c_str());
    }
    return round_tripped == original;
}
}

BOOST_AUTO_TEST_CASE(compress_transaction_basic)
{
    CMutableTransaction outputm;
    outputm.nVersion = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = CScript();

    round_trip_compress_transaction(outputm);
}
/*
BOOST_AUTO_TEST_CASE(compress_transaction_corpus)
{
    int counter = 0;
    int success = 0;
    int factor = 15;
    CSerializeData data;

    DIR* d = opendir("test-tx");
    for (struct dirent* ent = readdir(d); ent; ent = readdir(d)) {

        data.resize(1000000);

        if ((counter & factor) == 0) {
            std::cout << counter << '\n';
            factor = (factor + 1) * 2 - 1;
        }
        std::string filename = "test-tx/";
        filename += ent->d_name;

        FILE* f = fopen(filename.c_str(), "rb");
        if (f == nullptr) continue;
        auto const len = fread(data.data(), 1, data.size(), f);
        if (len <= 0) {
            fclose(f);
            continue;
        }
        data.resize(len);
        CDataStream str(data.begin(), data.end(), SER_NETWORK, PROTOCOL_VERSION);

        try {
            ++counter;
            CMutableTransaction tx;
            str >> tx;
            bool const ret = round_trip_compress_transaction(tx);
            success += int(ret);
            if (!ret) {
                std::cout << "\nround-trip transaction: " << ent->d_name << '\n';
            }
            if (!ret) break;
        } catch (std::exception const& e) {
            std::cout << "\nround-trip transaction: " << ent->d_name << '\n';
            std::cerr << "failed with exception: " << e.what() << '\n';
            break;
        }
        fclose(f);
    }
    closedir(d);
    std::cout << "ran " << counter << " tests. " << success << " passed\n";
}

BOOST_AUTO_TEST_CASE(compress_transaction_roundtrip)
{
    CSerializeData data;
    data.resize(1000000);

    char const* filename = "test-tx/tx-00000";
    FILE* f = fopen(filename, "rb");
    BOOST_CHECK(f != nullptr);

    auto const len = fread(data.data(), 1, data.size(), f);
    BOOST_CHECK(len > 0);

    data.resize(len);

    CDataStream str(data.begin(), data.end(), SER_NETWORK, PROTOCOL_VERSION);

    try {
        CMutableTransaction tx;
        str >> tx;

        printf("=== original:\n%s\n\n", CTransaction(tx).ToString().c_str());

        bool const ret = round_trip_compress_transaction(tx);
        BOOST_CHECK(ret == true);
    } catch (std::exception const& e) {
        std::cout << "\nround-trip transaction: " << filename << '\n';
        std::cerr << "failed with exception: " << e.what() << '\n';
        BOOST_CHECK(false);
        return;
    }
    fclose(f);
}
*/
namespace
{
const unsigned char vchKey0[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const unsigned char vchKey1[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0};
const unsigned char vchKey2[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0};

struct KeyData
{
    CKey key0, key0C, key1, key1C, key2, key2C;
    CPubKey pubkey0, pubkey0C, pubkey0H;
    CPubKey pubkey1, pubkey1C;
    CPubKey pubkey2, pubkey2C;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        key0C.Set(vchKey0, vchKey0 + 32, true);
        pubkey0 = key0.GetPubKey();
        pubkey0H = key0.GetPubKey();
        pubkey0C = key0C.GetPubKey();
        *const_cast<unsigned char*>(&pubkey0H[0]) = 0x06 | (pubkey0H[64] & 1);

        key1.Set(vchKey1, vchKey1 + 32, false);
        key1C.Set(vchKey1, vchKey1 + 32, true);
        pubkey1 = key1.GetPubKey();
        pubkey1C = key1C.GetPubKey();

        key2.Set(vchKey2, vchKey2 + 32, false);
        key2C.Set(vchKey2, vchKey2 + 32, true);
        pubkey2 = key2.GetPubKey();
        pubkey2C = key2C.GetPubKey();
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(compress_transaction_with_scripts)
{
    const KeyData keys;

    CMutableTransaction outputm;
    outputm.nVersion = 1;
    outputm.vin.resize(2);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    outputm.vin[1].prevout.SetNull();
    outputm.vin[1].scriptSig = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    outputm.vout.resize(2);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG;
    outputm.vout[1].nValue = 1;
    outputm.vout[1].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    round_trip_compress_transaction(outputm);
}

BOOST_AUTO_TEST_CASE(kn_coding)
{
    BOOST_CHECK(KNCoder(0, 0) == 3);
    BOOST_CHECK(KNCoder(0, 1) == 3);
    BOOST_CHECK(KNCoder(0, 2) == 4);
    BOOST_CHECK(KNCoder(0, 3) == 6);
    BOOST_CHECK(KNCoder(0, 4) == 9);
    BOOST_CHECK(KNCoder(0, 5) == 13);
    BOOST_CHECK(KNCoder(0, 6) == 18);
    BOOST_CHECK(KNCoder(0, 7) == 24);
    BOOST_CHECK(KNCoder(0, 8) == 31);
    BOOST_CHECK(KNCoder(0, 9) == 39);

    BOOST_CHECK(KNCoder(1, 0) == 0);
    BOOST_CHECK(KNCoder(1, 1) == 0);
    BOOST_CHECK(KNCoder(1, 2) == 1);
    BOOST_CHECK(KNCoder(1, 3) == 0);
    BOOST_CHECK(KNCoder(1, 4) == 0);
    BOOST_CHECK(KNCoder(1, 5) == 0);
    BOOST_CHECK(KNCoder(1, 6) == 0);
    BOOST_CHECK(KNCoder(1, 7) == 0);
    BOOST_CHECK(KNCoder(1, 8) == 0);
    BOOST_CHECK(KNCoder(1, 9) == 0);

    BOOST_CHECK(KNCoder(2, 0) == 0);
    BOOST_CHECK(KNCoder(2, 1) == 0);
    BOOST_CHECK(KNCoder(2, 2) == 2);
    BOOST_CHECK(KNCoder(2, 3) == 3);
    BOOST_CHECK(KNCoder(2, 4) == 4);
    BOOST_CHECK(KNCoder(2, 5) == 0);
    BOOST_CHECK(KNCoder(2, 6) == 0);
    BOOST_CHECK(KNCoder(2, 7) == 0);
    BOOST_CHECK(KNCoder(2, 8) == 0);
    BOOST_CHECK(KNCoder(2, 9) == 0);

    BOOST_CHECK(KNCoder(3, 0) == 0);
    BOOST_CHECK(KNCoder(3, 1) == 0);
    BOOST_CHECK(KNCoder(3, 2) == 0);
    BOOST_CHECK(KNCoder(3, 3) == 0);
    BOOST_CHECK(KNCoder(3, 4) == 5);
    BOOST_CHECK(KNCoder(3, 5) == 6);
    BOOST_CHECK(KNCoder(3, 6) == 0);
    BOOST_CHECK(KNCoder(3, 7) == 0);
    BOOST_CHECK(KNCoder(3, 8) == 0);
    BOOST_CHECK(KNCoder(3, 9) == 0);

    BOOST_CHECK(KNCoder(4, 0) == 7);
    BOOST_CHECK(KNCoder(4, 1) == 7);
    BOOST_CHECK(KNCoder(4, 2) == 8);
    BOOST_CHECK(KNCoder(4, 3) == 10);
    BOOST_CHECK(KNCoder(4, 4) == 13);
    BOOST_CHECK(KNCoder(4, 5) == 17);
    BOOST_CHECK(KNCoder(4, 6) == 22);
    BOOST_CHECK(KNCoder(4, 7) == 28);
    BOOST_CHECK(KNCoder(4, 8) == 35);
    BOOST_CHECK(KNCoder(4, 9) == 43);
}

valtype vec(int size)
{
    return valtype(size, std::uint8_t(size & 0xff));
}

BOOST_AUTO_TEST_CASE(encode_push_only_test)
{
    using r = std::pair<bool, std::vector<valtype>>;

    BOOST_CHECK(encode_push_only(CScript(OP_0)) == r(true, {{}}));
    BOOST_CHECK(encode_push_only(CScript() << 0) == r(true, {{}}));
    BOOST_CHECK(encode_push_only(CScript() << 1) == r(true, {{1}}));
    BOOST_CHECK(encode_push_only(CScript() << 2) == r(true, {{2}}));
    BOOST_CHECK(encode_push_only(CScript() << 16) == r(true, {{16}}));
    BOOST_CHECK(encode_push_only(CScript() << 17) == r(true, {{17}}));
    BOOST_CHECK(encode_push_only(CScript() << 127) == r(true, {{127}}));
    BOOST_CHECK(encode_push_only(CScript() << 0x81) == r(true, {{0x81, 0}}));
    BOOST_CHECK(encode_push_only(CScript() << 255) == r(true, {{255, 0}}));
    BOOST_CHECK(encode_push_only(CScript() << vec(2)) == r(true, {vec(2)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(3)) == r(true, {vec(3)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(4)) == r(true, {vec(4)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(5)) == r(true, {vec(5)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(6)) == r(true, {vec(6)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(75)) == r(true, {vec(75)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(76)) == r(true, {vec(76)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(255)) == r(true, {vec(255)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(256)) == r(true, {vec(256)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(65535)) == r(true, {vec(65535)}));
    BOOST_CHECK(encode_push_only(CScript() << vec(65536)) == r(true, {vec(65536)}));
    BOOST_CHECK(encode_push_only(CScript(OP_1NEGATE)) == r(true, {{0x81}}));

    // an empty scripts are not considered push only, as they indicate a script
    // witness
    BOOST_CHECK(encode_push_only(CScript()) == r(false, {}));

    // combinations of push operations
    BOOST_CHECK(encode_push_only(CScript() << vec(65536) << 0) == r(true, {vec(65536), {}}));
    BOOST_CHECK(encode_push_only(CScript() << vec(5) << OP_0 << 255) == r(true, {vec(5), {}, {255, 0}}));
    BOOST_CHECK(encode_push_only(CScript() << 24 << 15 << vec(5) << OP_0 << 255)
        == r(true, {{24}, {15}, vec(5), {}, {255, 0}}));

    // this fails because operator<< does not encode the special case of a
    // single "1" as OP_1, and our encode_push_only() requires scripts to use the
    // optimal encoding
    BOOST_CHECK(encode_push_only(CScript() << vec(1)) == r(false, {}));

    // not a Push operation
    BOOST_CHECK(encode_push_only(CScript(OP_ROT)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_NOP)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_IF)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_ELSE)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_EQUAL)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_SIZE)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_DUP)) == r(false, {}));
    BOOST_CHECK(encode_push_only(CScript(OP_INVALIDOPCODE)) == r(false, {}));

    // not a push operation, but the first one is still preserved in the output
    BOOST_CHECK(encode_push_only(CScript() << vec(2) << OP_DUP) == r(false, {vec(2)}));

    // "overlong" encoding. e.g. use OP_PUSHDATA2 when the size would fit in a
    // OP_PUSHDATA1
    {
        CScript s;
        s.insert(s.end(), OP_PUSHDATA2);
        std::array<uint8_t, 2> data;
        WriteLE16(data.data(), 130);
        s.insert(s.end(), data.begin(), data.end());
        auto test_vec = vec(130);
        s.insert(s.end(), test_vec.begin(), test_vec.end());

        // this fails because 130 bytes are expected to be pushed with
        // OP_PUSHDATA1, since 1 byte of length prefix is enough, but this test
        // use OP_PUSHDATA2, using 2 bytes length prefix
        BOOST_CHECK(encode_push_only(s) == r(false, {}));
    }

    // garbage
    {
        CScript s;
        valtype test_vec = {230, 45, 134,64,61,24,234,75,2,90};
        s.insert(s.end(), test_vec.begin(), test_vec.end());

        BOOST_CHECK(encode_push_only(s) == r(false, {}));
    }
}

void test_script_roundtrip(CScript const s)
{
    auto const ret = encode_push_only(s);
    BOOST_CHECK(ret.first);
    auto const script = decode_push_only(MakeSpan(ret.second));
    BOOST_CHECK(s == script);
}

BOOST_AUTO_TEST_CASE(decode_push_only_test)
{
    test_script_roundtrip(CScript(OP_0));
    test_script_roundtrip(CScript() << 0);
    test_script_roundtrip(CScript() << 1);
    test_script_roundtrip(CScript() << 2);
    test_script_roundtrip(CScript() << 16);
    test_script_roundtrip(CScript() << 17);
    test_script_roundtrip(CScript() << 127);
    test_script_roundtrip(CScript() << 0x81);
    test_script_roundtrip(CScript() << 255);
    test_script_roundtrip(CScript() << vec(2));
    test_script_roundtrip(CScript() << vec(3));
    test_script_roundtrip(CScript() << vec(4));
    test_script_roundtrip(CScript() << vec(5));
    test_script_roundtrip(CScript() << vec(6));
    test_script_roundtrip(CScript() << vec(75));
    test_script_roundtrip(CScript() << vec(76));
    test_script_roundtrip(CScript() << vec(255));
    test_script_roundtrip(CScript() << vec(256));
    test_script_roundtrip(CScript() << vec(65535));
    test_script_roundtrip(CScript() << vec(65536));
    test_script_roundtrip(CScript(OP_1NEGATE));
}

BOOST_AUTO_TEST_CASE(right_align_copy)
{
    using r = std::vector<uint8_t>;
    r const zero(10);
    r dest = zero;
    BOOST_CHECK(dest == (r{0,0,0,0,0,0,0,0,0,0}));

    // dest is larger than src
    right_align(MakeSpan(r{1, 2, 3, 4, 5}), MakeSpan(dest));
    BOOST_CHECK(dest == (r{0, 0, 0, 0, 0, 1, 2, 3, 4, 5}));

    dest = zero;

    // src is larger than dest
    right_align(MakeSpan(r{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}), MakeSpan(dest));
    BOOST_CHECK(dest == (r{2, 3, 4, 5, 6, 7, 8, 9, 10, 11}));

    dest = zero;

    // src same size as dest
    right_align(MakeSpan(r{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), MakeSpan(dest));
    BOOST_CHECK(dest == (r{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
}

BOOST_AUTO_TEST_CASE(strip_sig)
{
    using r = valtype;
    // signature encoding:
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

    // R is 3 bytes long (10, 11, 12)
    // S is 4 bytes long (13, 14, 15, 16)
    // no sighash
    BOOST_CHECK(StripSig(r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 0}, false)
        == (r{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 14, 15, 16, 0}));

    // R is 3 bytes long (10, 11, 12)
    // S is 33 bytes lon
    // no sighash
    BOOST_CHECK(StripSig(r{0x30, 40
        , 0x02, 3, 10, 11, 12 // R
        , 0x02, 33, 0 // S
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0}, false)
        == (r{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0}));

    // R is 33 bytes long
    // S is 3 bytes lon
    // no sighash
    BOOST_CHECK(StripSig(r{0x30, 40
        , 0x02, 33, 0
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0x02, 3, 10, 11, 12
        , 0}, false)
        == (r{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 0}));

    // with sighash
    BOOST_CHECK(StripSig(r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 1}, true)
        == (r{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 14, 15, 16}));
}

BOOST_AUTO_TEST_CASE(pad_sig)
{
    using r = valtype;

    auto const padded0 = r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 0};
    auto const padded1 = r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 1};
    auto const padded3 = r{0x30, 11, 0x02, 3, 10, 11, 12, 0x02, 4, 13, 14, 15, 16, 3};

    // if sighashall is true, the flags *must* be 1
    BOOST_CHECK(PadSig(MakeSpan(StripSig(padded0, false)), false) == padded0);
    BOOST_CHECK(PadSig(MakeSpan(StripSig(padded1, false)), false) == padded1);
    BOOST_CHECK(PadSig(MakeSpan(StripSig(padded3, false)), false) == padded3);
    BOOST_CHECK(PadSig(MakeSpan(StripSig(padded1, true)), true) == padded1);

    {
    auto const padded = r{0x30, 40
        , 0x02, 3, 10, 11, 12 // R
        , 0x02, 33, 0 // S
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    BOOST_CHECK(PadSig(MakeSpan(StripSig(padded, false)), false) == padded);
    }

    {
    auto const padded = r{0x30, 40
        , 0x02, 33, 0
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0x02, 3, 10, 11, 12
        , 0};
    BOOST_CHECK(PadSig(MakeSpan(StripSig(padded, false)), false) == padded);
    }

    {
    auto const padded = r{0x30, 40
        , 0x02, 33, 0
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        , 0x02, 3, 10, 11, 12
        , 1};
    BOOST_CHECK(PadSig(MakeSpan(StripSig(padded, true)), true) == padded);
    }
}

namespace {

valtype make_test_pubkey()
{
    static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    CKey bsecret1 = DecodeSecret(strSecret1);
    BOOST_CHECK(bsecret1.IsValid());
    CPubKey k = bsecret1.GetPubKey();
    return valtype(k.begin(), k.end());
}
}

BOOST_AUTO_TEST_CASE(valid_pubkey)
{
    valtype const pubkey = make_test_pubkey();

    BOOST_CHECK(IsValidPubKey(pubkey));

    {
        valtype broken = pubkey;
        broken.erase(broken.begin());
        BOOST_CHECK(!IsValidPubKey(broken));
    }

    {
        valtype broken = pubkey;
        broken.erase(broken.end() - 1);
        BOOST_CHECK(!IsValidPubKey(broken));
    }

    {
        valtype broken = pubkey;
        broken[0] -= 0x2;
        BOOST_CHECK(!IsValidPubKey(broken));
    }
}

BOOST_AUTO_TEST_CASE(strip_pubkey)
{
    {
    // matching the pattern for a regular public key
    valtype const pubkey = {
        0x04, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 1 };

    valtype const stripped = StripPubKey(pubkey);
    BOOST_CHECK(stripped == (valtype{
        0x03, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0 }));
    }

    {
    // does not have the LSB set in the last byte, store verbatim
    valtype const pubkey = {
        0x04, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0 };

    valtype const stripped = StripPubKey(pubkey);
    BOOST_CHECK(stripped == (valtype{
        0x02, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0 }));
    }

    {
    // is not 65 bytes long
    valtype const pubkey = {
        0x04, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0
        , 0 };

    valtype const stripped = StripPubKey(pubkey);
    BOOST_CHECK(stripped == (valtype{
        0x02, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        , 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0
        , 0 }));
    }

    {
    // roundtrip
    valtype const pubkey = make_test_pubkey();
    valtype stripped = StripPubKey(pubkey);
    // when we "decode" a pub key, we pass in the key prefix as an argument,
    // rather than it being the first byte in the key. So, we have to remove
    // it here, and pass it in as a separate argument.
    uint8_t const template_type = stripped[0];
    stripped.erase(stripped.begin());
    valtype const result = PadPubKey(MakeSpan(stripped), template_type);
    BOOST_CHECK(result == pubkey);
    }
}

// TODO: add test for PadMultiSig
// TODO: add test for PadHash

BOOST_AUTO_TEST_SUITE_END()
