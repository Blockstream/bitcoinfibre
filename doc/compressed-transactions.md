(see http://people.xiph.org/~greg/compacted_txn.txt for original)

# Goal

This is a proposal for a transaction compression scheme. It does not change signatures, or txids, or hashes. It's merely
a more efficient encoding for transactions, and software using it should always convert the transactions back to the
normative standard transaction encoding before computing txids and wtxids.

It is designed to be compact, but without relying on any context beyond a single transaction. This makes it applicable for
transaction and block storage on disk, for transfer in the P2P network (including inside BIP152), and for storage in
wallet software.

# Specification

Transaction serialization:
* TxHeader: byte
* nLockTime: varint or uint32 (if not implied by TxHeader)
* nVersion: uint32 (if not implied by TxHeader)
* For each input:
  * TxInHeader: byte (includes a bit to indicate whether more inputs follow)
  * prevout.n: varint (if not implied by TxHeader)
  * nSequence: uint32 (if not implied by TxHeader)
  * prevout.hash: uint256 (if not implied by TxHeader)
  * TxInScriptHeader: varint
  * For each scriptSig item and each scriptWitness push (see below):
    * TxInScriptAtom: varint
    * Data: byte[] (size implied by TxInScriptAtom)
* For each output:
  * TxOutHeader: byte (includes a bit to indicate whether more outputs follow)
  * Data: byte[] (size implied by TxOutHeader)
  * Amount: varint

## TxHeader

TxHeader = LockTimeCode + TxVersionCode * 3
* LockTimeCode:
  * 0: nLockTime = 0
  * 1: nLockTime explicitly coded as varint
  * 2: nLockTime explicitly coded as uint32
* TxVersionCode:
  * 0-14: nLockTime = TxVersionCode
  * 15: nLockTime explicitly coded as uint32

Values above 47 are reserved for future versions.

## TxInHeader

TxInHeader = TxInCont + PrevOutCode * 2 + SequenceCode * 50
* TxInCont:
  * 0: another TxIn follows this one
  * 1: this is the last TxIn
* PrevOutCode:
  * 0-22: prevout.n = PrevOutCode
  * 23: coinbase (prevout.hash = uint256(0), prevout.n = 0xFFFFFFFF)
  * 24: prevout.n explicitly coded as varint
* SequenceCode:
  * 0: nSequence = 0
  * 1: nSequence = 0xFFFFFFFF (*SEQUENCE_FINAL*)
  * 2: nSequence = 0xFFFFFFFE
  * 3: nSequence is last explicitly coded value (or, if no explicitly coded value came before, 0xFFFFFFFD)
  * 4: nSequence is explicitly coded as uint32
  * 5: reserved for future use

Values above 249 are reserved for future versions.

## TxInScriptHeader & TxInScriptAtoms

TxInScriptHeader:
* 0-9: Backreference
* 10: *empty* scriptSig and scriptWitness are both empty
* 11: *custom* scriptSig and scriptWitness are both non-empty and explicitly coded. Two sequences of Atoms follow, one for the scriptSig items and one for the scriptWitness items.
* 12 + Atom*3: *scriptSig-only*, with its first Atom encoded inside the header.
* 13 + Atom*3: *scriptWitness-only*, with its first Atom encoded inside the header.
* 14 + Atom*3: *scriptWitness-P2SH*, with only the scriptWitness explicitly encoded, and scriptSig reconstructed as P2SH redeemscript for v0 witness.

TxInScriptAtom = TxInScriptCont + 2 * AtomType:
* TxInScriptCont: 1 if this is not the last Atom in the sequence.
* AtomType (for scriptSig items):
  * 4 * Compressed + 2 * OddY + SigHashTypeOne: *pubkey+sig*
  * 8 + SigHashTypeOne: *sig*
  * 10-26: *OP_N* (where N = AtomType - 10)
  * 27 + 4 * Len + 2 * Raw + IsPush (scriptSig): *custom*
* AtomType (for scriptWitness items):
  * 2 * OddY + SigHashTypeOne: *pubkey+sig*
  * 4 + SigHashTypeOne: *sig*
  * 6-22: *OP_N* (where N = AtomType - 6)
  * 23 + 2 * Len + IsPush: *custom*

### Data bytes
* *pubkey+sig*:
  * byte[32] for the pubkey X coordinate.
  * byte[64] for the signature.
  * byte[1] for the sighashtype (if SigHashTypeOne = 0).
* *sig*:
  * byte[64] for the signature.
  * byte[1] for the sighashtype (if SigHashTypeOne = 0).
* *custom*:
  * byte[Len] for the data.
* Everything else:
  * None.

### Encoding of signatures

### Encoding of pubkeys

### Encoding of custom data

### Backreferences

## TxOutHeader

TxOutHeader = TxOutCont + 2 * TxOutCode
* TxOutCont: 1 if more TxOuts follow
* TxOutCode:
  * 0: P2PKH (20 bytes follow)
  * 1: P2SH (20 bytes follow)
  * 2: P2WPKH (20 bytes follow)
  * 3: P2WSH (32 bytes follow)
  * 4 + 2*Compressed + OddY: P2PK (32 bytes follow)
  * 8 + N (N in 0..15): Witness VN (+ 32 bytes)
  * 24 + N (N in 0..15): Witness VN (+ 1 byte length L) (+ L bytes)
  * 40 + L (L in 0..75): Arbitrary data (+ L bytes)
  * 116: Custom (+ varint L) (+ (L+76) bytes)

Values above 233 are reserved for future versions.

## Amount

Amounts are encoded as a transformed number:
  * amount 0: 0
  * amount x * 10^e (e in [0..8]): 1 + 10 * (9 * [b..c] + [a] - 1) + e
  * amount x * 10^9: 1 + 10 * ([a..b] - 1) + 9

# Analysis

