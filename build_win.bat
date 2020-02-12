@ECHO ON

RMDIR /Q /S build
MKDIR build
PUSHD build

conan install .. 
cmake .. -G "NMake Makefiles"  -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="/MT"
cmake --build . --config Release

bin\trojan.exe
