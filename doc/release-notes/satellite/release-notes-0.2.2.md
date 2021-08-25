Bitcoin Satellite 0.2.2 Release Notes
====================

Bitcoin Satellite version 0.2.2 is now available for Ubuntu, Fedora, and CentOS
at:

  - [Launchpad (Debian packages)](https://launchpad.net/~blockstream/+archive/ubuntu/satellite)
  - [Copr (RPM package)](https://copr.fedorainfracloud.org/coprs/blockstream/satellite/)

This minor release includes small improvements and bug fixes.

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

Bitcoin Satellite 0.2.2 is supported and tested on the following Linux distributions:
- The latest two Ubuntu LTS releases.
- The latest two Fedora releases.
- CentOS 8.

Bitcoin Core Version
==============

Bitcoin Satellite is a fork of Bitcoin Core. This specific release (version
0.2.2) is based on Bitcoin Core 0.21.1.

Notable changes
===============

Misbehavior on full synchronization via UDP multicast
-----------------------------------

The full node synchronization via UDP multicast (e.g., through the Blockstream
Satellite stream) would previously fail if executed after the initial download
of block headers from internet peers. For example, if the node had hybrid
connectivity (satellite and internet) or spent some time connected on the
peer-to-peer (p2p) network before initiating the full sync via UDP multicast
only. In both cases, the node would likely download all block headers over the
internet. After that, any block received via UDP multicast would be ignored
whenever the corresponding header was already downloaded, as if the entire block
was already available.

This version fixes the condition for skipping an FEC-encoded block received via
a UDP multicast stream. In addition to confirming the local block index already
has an entry for the block, it also ensures the corresponding block data is
available. Only in that scenario, it skips the FEC object to avoid unnecessary
computations. By doing so, the satellite-based full synchronization procedure
can run correctly despite a previous download of block headers over the
internet.

0.2.2 Changelog
=================

### FEC
- Fix the blocking of file descriptors used to store partial FEC objects on
  memory-mapped files. Release the descriptors immediately after memory mapping.

### UDP Multicast Rx
- Fix the skipping of FEC-encoded blocks with pre-existing entries on the local
  block index. Skip an FEC block only if the corresponding hash is present on the
  local index and the block data is entirely available.
- Review the partial block timeout rule. Time blocks out based on the last
  useful FEC chunk reception instead of the partial block creation timestamp.
  Also, do not time out partial blocks coming from trusted peers while the local
  node is not in sync with the trusted peers.
- Review the filename of partial blocks stored in disk to fix the
  incompatibility with NTFS file systems.
- Fix runtime error thrown upon the reception of an unsupported txn codec. Drop
  the partial block instead of crashing the application.

### UDP Multicast Tx
- Include the number of window blocks in the result returned by the
  gettxwindowinfo RPC.

