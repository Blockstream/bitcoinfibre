Bitcoin Satellite 0.2.4 Release Notes
====================

Bitcoin Satellite version 0.2.4 is now available. This release updates the
underlying Bitcoin Core version to 23.0.

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
have it
[installed](https://blockstream.github.io/satellite/doc/quick-reference.html#cli-installation-and-upgrade),
run:

```
blocksat-cli deps update --btc
```

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

Bitcoin Satellite 0.2.4 is supported and tested on the following Linux
distributions:

- Ubuntu LTS (20.04 and 22.04).
- Fedora (34 and 35).
- Debian (10 and 11).
- Raspberry Pi OS 11.
- CentOS 8.

Bitcoin Core Version
==============

Bitcoin Satellite is a fork of Bitcoin Core. This specific release (version
0.2.4) is based on Bitcoin Core 23.0.

0.2.4 Changelog
=================

- Add option to configure the UDP multicast Tx ring buffer depth.
- Add option to exit the UDP Tx loop with non-empty buffers.
