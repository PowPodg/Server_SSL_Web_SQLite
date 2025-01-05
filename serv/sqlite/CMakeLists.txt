cmake_minimum_required (VERSION 3.22)
project(sql_lib)

file (GLOB CM "*.c" HM "*.h")

add_library(sql_lib STATIC ${CM} ${HM})

target_include_directories(sql_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})




