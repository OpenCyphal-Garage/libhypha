# Example CMake Import

After building Hypha Ip and installing to the CMAKE_INSTALL_PREFIX, use the same location here.

```bash
cmake -B build -S . -DCMAKE_INSTALL_PREFIX=../../build/install
cmake --build build --target all
```
