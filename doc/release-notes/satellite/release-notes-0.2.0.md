Bitcoin Satellite 0.2.0 Release Notes
====================

Bitcoin Satellite version 0.2.0 is now available for Ubuntu, Fedora, and CentOS
at:

  - [Launchpad (Debian packages)](https://launchpad.net/~blockstream/+archive/ubuntu/satellite)
  - [Copr (RPM package)](https://copr.fedorainfracloud.org/coprs/blockstream/satellite/)

This release includes new features, bug fixes, and various performance
improvements.

Please report bugs using the issue tracker:

  <https://github.com/Blockstream/bitcoinsatellite/issues>

Alternatively, contact us at:

  - <https://help.blockstream.com/>
  - #blockstream-satellite IRC channel on freenode

How to Upgrade
==============

The easiest way to upgrade is by using the
[`blocksat-cli`](https://github.com/Blockstream/satellite/blob/master/doc/quick-reference.md),
the Blockstream Satellite command-line interface (CLI). Assuming you already
have it installed, run:

```
blocksat-cli deps update --btc
```

Otherwise, you can [install the
CLI](https://github.com/Blockstream/satellite/blob/master/doc/quick-reference.md#1-cli-installation-and-upgrade)
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

Bitcoin Satellite is supported and tested on Linux distributions using the
latest Ubuntu, Fedora, and CentOS releases.


Bitcoin Core Version
==============

Bitcoin Satellite is a fork of Bitcoin Core. This specific release (version
0.2.0) is based on Bitcoin Core 0.19.1.

0.2.0 Changelog
=================

### UDP Multicast Tx
- Refactor the UDP Tx packet scheduler implementation on `udpnet.cpp`.
- Implement a standalone ring buffer class and use it on the new scheduler.
- Add a class to handle throttling in the UDP packet scheduler and reuse it to
  implement the throttling of txns sent over UDP multicast.
- Remove the tracking of block Tx window cycles (with `debug=udpmulticast`) due
  to inaccuracies that derive from the chunk interleaving approach.
- Fix checksum initialization on the UDP message header.
- Fix the computation of physical and logical UDP multicast stream indexes.
- Configure option `udpmulticasttx` based on an independent configuration file
  instead of using comma-separated arguments.
- Support the independent enabling of the block and txn streams composing each
  UDP multicast Tx instance.
- Support control of FEC overhead applied to block repetition loops via the new
  `udpmulticasttx` configuration file.
- Fix rounding of variable overhead used on FEC encoding.

### UDP Multicast Rx
- Fix the UDP multicast Rx bitrate measurements that were not considering the
  variable-length UDP packets used for txns.

### FEC
- Add unit tests covering `fec.cpp`.
- Support FEC decoding in both memory and mmap modes. Use the memory mode for
  new blocks and the mmap approach for historic (repeated) blocks.
- Optimize the fetching of wirehair-decoded FEC objects that are not pre-filled
  (i.e., historic blocks and large mempool txns).
- Update the naming format adopted for memory-mapped files storing partial
  FEC-encoded block data.
- Support persistence of partially-received FEC-encoded blocks across
  sessions. Keep the partial block files on disk until they are entirely decoded
  and reload partially-received block files on startup.

### RPCs

#### Tx RPCs
- Add RPC `gettxqueueinfo` to fetch information from the transmit queues active
  in the UDP Tx packet scheduler.
- Add RPC `gettxwindowinfo` to fetch the UDP multicast Tx block window status
  and remove this information from the previous periodic debug logs.
- Add RPC `gettxntxinfo` for monitoring of mempool txn transmissions.
- Add RPC `txblock` for re-transmission of any arbitrary block (specified by
  height) over the UDP multicast Tx instances.

#### Rx RPCs
- Add RPC `getfechitratio` to fetch the txn and FEC chunk hit ratios
  corresponding to the txn/chunk pre-filling mechanism.
- Add RPC `getudpmulticastinfo` to read UDP multicast Rx information, including
  the measured bit rates.
- Add RPC `getoooblocks` to obtain information regarding out-of-order blocks.

### Debug options
- Drop the previous optional debug printing of FEC chunk stats, deprecated in
  favor of debugging using the `getchunkstats` RPC.
