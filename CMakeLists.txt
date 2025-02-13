cmake_minimum_required(VERSION 3.16)

project(file_monitor LANGUAGES C)

set(CMAKE_C_STANDARD 23)
cmake_policy(SET CMP0115 NEW)

find_package(OpenSSL REQUIRED)

add_executable(client client.c common/cmp.c common/cmp.h
    common/BufferRing.h
    common/BufferRing.c)

add_executable(server server.c common/cmp.c common/cmp.h
    common/BufferRing.h
    common/BufferRing.c)

target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)

