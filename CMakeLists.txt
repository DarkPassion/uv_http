cmake_minimum_required(VERSION 3.8)

project(uv-http)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

set(UV_DIR deps/libuv)
set(SSL_DIR deps/openssl)

set(HTTP_PARSER_DIR deps/http-parser)

include_directories(
        ${UV_DIR}/include/
        ${UV_DIR}/src/
        ${SSL_DIR}/include/
        ${HTTP_PARSER_DIR}
        src)

link_directories(${SSL_DIR}/libs)

add_definitions("-DDEBUG -D_DEBUG -DTEST_SELF -O0")
#add_definitions("-DNDEBUG -D_NDEBUG -O3")


set(uv_dir deps/libuv/src)
set(uv_sources
        ${uv_dir}/fs-poll.c
        ${uv_dir}/inet.c
        ${uv_dir}/threadpool.c
        ${uv_dir}/timer.c
        ${uv_dir}/uv-common.c
        ${uv_dir}/uv-data-getter-setters.c
        ${uv_dir}/version.c)

list(APPEND uv_sources
        ${uv_dir}/unix/async.c
        ${uv_dir}/unix/core.c
        ${uv_dir}/unix/dl.c
        ${uv_dir}/unix/fs.c
        ${uv_dir}/unix/getaddrinfo.c
        ${uv_dir}/unix/getnameinfo.c
        ${uv_dir}/unix/loop-watcher.c
        ${uv_dir}/unix/loop.c
        ${uv_dir}/unix/pipe.c
        ${uv_dir}/unix/poll.c
        ${uv_dir}/unix/process.c
        ${uv_dir}/unix/signal.c
        ${uv_dir}/unix/stream.c
        ${uv_dir}/unix/tcp.c
        ${uv_dir}/unix/thread.c
        ${uv_dir}/unix/tty.c
        ${uv_dir}/unix/udp.c)

if(CMAKE_SYSTEM_NAME MATCHES "Android|Darwin|Linux|OS/390")
    list(APPEND uv_sources ${uv_dir}/unix/proctitle.c)
endif()


if(CMAKE_SYSTEM_NAME MATCHES "Darwin|DragonFly|FreeBSD|NetBSD|OpenBSD")
    list(APPEND uv_sources ${uv_dir}/unix/bsd-ifaddrs.c ${uv_dir}/unix/kqueue.c)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND uv_defines _DARWIN_UNLIMITED_SELECT=1 _DARWIN_USE_64_BIT_INODE=1)
    list(APPEND uv_sources
            ${uv_dir}/unix/darwin-proctitle.c
            ${uv_dir}/unix/darwin.c
            ${uv_dir}/unix/fsevents.c)
endif()


file(GLOB DEPS_SRC
        ${HTTP_PARSER_DIR}/*.c)

file(GLOB C_SRC
        src/*.c
        src/util/*c)

file(GLOB CPP_SRC
        src/*.cpp src/*.cc
        src/util/*.cpp src/util/*.cc
        src/http/*.cpp src/http/*.cc
        src/client/*.cpp src/client/*.cc
        src/server/*.cpp src/server/*.cc
        src/data/*.cpp src/data/*.cc
        src/test/*.cpp src/test/*.cc)


add_executable(uv-http ${DEPS_SRC} ${C_SRC} ${CPP_SRC} ${uv_sources})

target_link_libraries(uv-http ssl crypto)
#link_libraries(uv-http uv)



