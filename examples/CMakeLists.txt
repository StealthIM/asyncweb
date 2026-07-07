# asyncweb 示例 —— 用安装后的 find_package 方式消费 asyncweb。
#
#   # 先装 libcoro + asyncweb 到某个 prefix (见各自 README), 然后:
#   cmake -B build -DCMAKE_PREFIX_PATH=/your/prefix
#   cmake --build build
#   ./build/http_get http://postman-echo.com/get
#   ./build/http_server
cmake_minimum_required(VERSION 3.16)
project(asyncweb_examples C)

set(CMAKE_C_STANDARD 11)

find_package(asyncweb REQUIRED)   # 透传拉入 libcoro + SSL 后端

add_executable(http_get http_get.c)
target_link_libraries(http_get PRIVATE asyncweb::asyncweb)

add_executable(http_server http_server.c)
target_link_libraries(http_server PRIVATE asyncweb::asyncweb)
