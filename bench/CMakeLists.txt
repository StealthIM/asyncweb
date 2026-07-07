# asyncweb 性能基线 —— 用安装后的 find_package 方式构建。
#   cmake -B build -DCMAKE_PREFIX_PATH=/your/prefix
#   cmake --build build
#   /usr/bin/time -v ./build/http_bench   # -v 附带峰值 RSS
cmake_minimum_required(VERSION 3.16)
project(asyncweb_bench C)

set(CMAKE_C_STANDARD 11)

find_package(asyncweb REQUIRED)

add_executable(http_bench http_bench.c)
target_link_libraries(http_bench PRIVATE asyncweb::asyncweb)
