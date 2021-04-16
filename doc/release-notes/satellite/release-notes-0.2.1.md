Bitcoin Satellite 0.2.1 Release Notes
====================

Bitcoin Satellite version 0.2.1 is now available for Ubuntu, Fedora, and CentOS
at:

  - [Launchpad (Debian packages)](https://launchpad.net/~blockstream/+archive/ubuntu/satellite)
  - [Copr (RPM package)](https://copr.fedorainfracloud.org/coprs/blockstream/satellite/)

This is a new minor version release including bug fixes.

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
latest two Ubuntu LTS, Fedora, and CentOS releases.

Bitcoin Core Version
==============

Bitcoin Satellite is a fork of Bitcoin Core. This specific release (version
0.2.1) is based on Bitcoin Core 0.19.1.

0.2.1 Changelog
=================

### FEC
- Update the Wirehair and cm256 sources to their latest versions.
- Fix fixture incompatibility on the FEC unit tests.
- Remove FEC test dependencies on Boost 1.61.
- Move the FEC implementation to a dedicated static library and assign the
  specific instruction subsets required to build it.
- Fix compilation based on native architecture (`march=native`) used previously
  to compile the FEC sources.
