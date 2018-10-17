# Build

We'll only cover the build process on Linux since we will be providing Windows and macOS binaries. Building trojan on every platform is similar.

## Dependencies

Install these dependencies before you build:

- [CMake](https://cmake.org/) >= 3.7.2
- [Boost](http://www.boost.org/) >= 1.54.0
- [OpenSSL](https://www.openssl.org/) >= 1.0.2
- [libmysqlclient](https://dev.mysql.com/downloads/connector/c/)

For Debian users, run `sudo apt -y install build-essential cmake libboost-system-dev libboost-program-options-dev libssl-dev default-libmysqlclient-dev` to install all the necessary dependencies.

## Clone

Type in

```bash
git clone https://github.com/trojan-gfw/trojan.git
cd trojan/
```

to clone the project and go into the directory.

## Build and Install

Type in

```bash
mkdir build
cd build/
cmake ..
make
ctest
sudo make install
```

to build, test, and install trojan. If everything goes well you'll be able to use trojan.

The `cmake ..` command can be extended with the following options:

- `ENABLE_MYSQL`
    - `-DENABLE_MYSQL=ON`: build with MySQL support (default).
    - `-DENABLE_MYSQL=OFF`: build without MySQL support.
- `ENABLE_SSL_KEYLOG` (OpenSSL >= 1.1.1)
    - `-DENABLE_SSL_KEYLOG=ON`: build with SSL KeyLog support (default).
    - `-DENABLE_SSL_KEYLOG=OFF`: build without SSL KeyLog support.
- `FORCE_TCP_FASTOPEN`
    - `-DFORCE_TCP_FASTOPEN=ON`: force build with TCP_FASTOPEN support.
    - `-DFORCE_TCP_FASTOPEN=OFF`: build with TCP_FASTOPEN support based on system capabilities (default).
- `SYSTEMD_SERVICE`
    - `-DSYSTEMD_SERVICE=AUTO`: detect systemd automatically and decide whether to install service (default).
    - `-DSYSTEMD_SERVICE=ON`: install systemd service unconditionally.
    - `-DSYSTEMD_SERVICE=OFF`: don't install systemd service unconditionally.
- `-DSYSTEMD_SERVICE_PATH=/path/to/systemd/system`: the path to which the systemd service will be installed (defaults to `/lib/systemd/system`).

After installation, config examples will be installed to `${CMAKE_INSTALL_DOCDIR}/examples/` and a server config will be installed to `${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json`.

[Homepage](.) | [Prev Page](authenticator) | [Next Page](usage)
