Bitcoin Satellite 0.2.3 Release Notes
====================

Bitcoin Satellite version 0.2.3 is now available. This minor release includes
improvements and bug fixes.

Please report bugs using the issue tracker:

  <https://github.com/Blockstream/bitcoinsatellite/issues>

Alternatively, contact us at:

  - <https://help.blockstream.com/>
  - #blockstream-satellite IRC channel on freenode

How to Upgrade
==============

The easiest way to upgrade is by using
[`blocksat-cli`](https://blockstream.github.io/satellite/doc/quick-reference.html),
the Blockstream Satellite command-line interface (CLI). Assuming you already
have it installed, run:

```
blocksat-cli deps update --btc
```

Otherwise, you can [install the
CLI](https://blockstream.github.io/satellite/doc/quick-reference.html#cli-installation-and-upgrade)
and run the above command.

Alternatively, you can upgrade Bitcoin Satellite manually by running the
following commands:

Ubuntu:
```
add-apt-repository ppa:blockstream/satellite
apt-get update
apt-get install --only-upgrade bitcoin-satellite
```

Debian:
```
add-apt-repository https://aptly.blockstream.com/satellite/debian/
apt-key adv --keyserver keyserver.ubuntu.com \
    --recv-keys 87D07253F69E4CD8629B0A21A94A007EC9D4458C
apt-get update
apt-get install --only-upgrade bitcoin-satellite
```

Raspbian:
```
add-apt-repository https://aptly.blockstream.com/satellite/raspbian/
apt-key adv --keyserver keyserver.ubuntu.com \
    --recv-keys 87D07253F69E4CD8629B0A21A94A007EC9D4458C
apt-get update
apt-get install --only-upgrade bitcoin-satellite
```

Fedora:
```
dnf copr enable blockstream/satellite
dnf upgrade bitcoin-satellite
```

CentOS:
```
yum copr enable blockstream/satellite
yum upgrade bitcoin-satellite
```

Compatibility
==============

Bitcoin Satellite 0.2.3 is supported and tested on the following Linux
distributions:

- Ubuntu LTS (18.04 and 20.04).
- Fedora (33 and 34).
- Debian (10 and 11).
- Raspberry Pi OS (10 and 11).
- CentOS 8.

Bitcoin Core Version
==============

Bitcoin Satellite is a fork of Bitcoin Core. This specific release (version
0.2.3) is based on Bitcoin Core 22.0.

Notable changes
===============

SIMD Compatibility
-----------------------------------

Bitcoin Satellite uses a SIMD-accelerated GF(256) Galois Field implementation
supporting the AVX2, SSSE3, and ARM Neon instruction sets. In runtime, the gf256
module detects whether the running machine features any of the supported SIMD
instruction sets and invokes the fastest available implementation. Nevertheless,
in addition to the runtime detection, the build system must also be configured
correctly. In particular, the build must restrict the usage of SIMD instructions
to the functions called conditionally depending on the instruction set
availability. Meanwhile, all other parts of the gf256 code (executed
unconditionally) shall not contain machine-specific SIMD instructions.
Otherwise, they can lead to illegal instruction errors when running on
incompatible machines. This requirement was failing on the previous package
version (Bitcoin Satellite v0.2.2). For example, the former package would crash
on a host supporting SSSE3 but not AVX2.

This release fixes SIMD incompatibilities on the gf256 implementation by
separating it into multiple SIMD-specific sources: `gf256_avx2`, `gf256_ssse3`,
and `gf256_neon`. In the new version, the build system enables AVX2 instructions
only when compiling `gf256_avx2.cpp`. Likewise, it allows SSSE3 instructions
only on `gf256_ssse3`, and so on. The program detects whether the
AVX2/SSSE3/NEON sets are available in runtime and invokes the appropriate
implementation. Meanwhile, the base `gf256` implementation (executed
unconditionally) does not use any machine-specific SIMD instructions.

0.2.3 Changelog
=================

### Bitcoind
- Print the Bitcoin Satellite version on initialization and the version command.

### FEC
- Fix the compilation of SIMD-accelerated gf256 calculations.
- Compile gf256 with SSSE3 and SSE2 instead of SSE3 when applicable.
- Support gf256's Neon implementation on AArch32.

### Transaction Compression
- Fix compression ambiguity on TxOuts with code 24.
- Support ending height on the `testcompression` RPC.

### UDP Multicast Rx
- Allow re-download of an out-of-order Rx block if not saved to the database.
- Reload the disk-stored partial blocks on a background task.
- Process disk-imported partial blocks immediately when fully decodable.
- Process the block as a tip block if at least one message carries the tip flag.
- Add removed state to partial blocks and prevent repeated processing attempts.
- Do not exit if the receive buffer size configuration fails.

### UDP Multicast Tx
- Add option to specify the transaction compression scheme on RPC `txblock`.
- Add option to save the UDP Multicast Tx window state using LevelDB.
- Restore the Tx window state using parallel asynchronous workers.
- Fix unnecessary polling for write space executed for empty Tx queues.
