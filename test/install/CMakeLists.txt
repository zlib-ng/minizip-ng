cmake_minimum_required(VERSION 3.13)
project(minizip-install-test C)

find_package(minizip REQUIRED)

add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE MINIZIP::minizip)
