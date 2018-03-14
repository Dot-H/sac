cmake_minimum_required(VERSION 2.8)

project(SAC C)
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -std=c99 -Os")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories("src/")

set(SRC
        src/main.c
        src/build.c
        src/patch-func.c
  )

add_executable(sac ${SRC})
target_link_libraries(sac dl)
