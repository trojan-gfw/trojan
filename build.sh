#!/bin/bash

set -e
set -x

rm -rf build
mkdir build
pushd build

conan install .. --settings=compiler.libcxx=libstdc++11
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

bin/trojan
