# Compilation

I'll only cover the build process on Linux since I will be providing Windows and macOS binaries and that building trojan on every platform is similar.

## Dependencies

Install these dependencies before you build:

- [CMake](https://cmake.org/) >= 2.8.12
- [Boost](http://www.boost.org/) >= 1.53.0
- [OpenSSL](https://www.openssl.org/) >= 1.0.2

For example, if you are using Ubuntu 14.04, you can type in

```bash
curl https://www.openssl.org/source/openssl-1.0.2l.tar.gz | tar xz && cd openssl-1.0.2l && sudo ./config shared && sudo make && sudo make install
sudo apt-get install cmake3 libboost-all-dev
```

to install all the dependencies.

## Clone

Type in

```bash
git clone https://github.com/GreaterFire/trojan.git
cd trojan/
git checkout stable
```

to clone the project and go into the directory and change to `stable` branch.

## Build

Type in

```bash
cmake . && make
```

to build the project. If everything goes well you'll get a binary called `trojan`.

[Homepage](.) | [Prev Page](config) | [Next Page](usage)
