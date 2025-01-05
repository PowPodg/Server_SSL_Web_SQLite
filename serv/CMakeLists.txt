cmake_minimum_required (VERSION 3.22)

project(serv_lib)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(serv_lib STATIC "HttpsServer.cpp" "HttpsServer.h")

target_include_directories(serv_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(json)
add_subdirectory(sqlite)

find_package(OpenSSL REQUIRED)

# Связываем статическую библиотеку jsoncpp с проектом
if(WIN32)
  target_link_libraries(serv_lib PRIVATE sql_lib json_lib OpenSSL::SSL OpenSSL::Crypto ws2_32)
else()
  target_link_libraries(serv_lib PRIVATE sql_lib json_lib OpenSSL::SSL OpenSSL::Crypto)
endif()