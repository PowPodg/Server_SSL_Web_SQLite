cmake_minimum_required(VERSION 3.22)

project(serv_coroutine_lib LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(serv_coroutine_lib STATIC
    "HttpsServerCoroutine.cpp"
    "HttpsServerCoroutine.h"
)

target_include_directories(serv_coroutine_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../serv
)

# Если json/sqlite уже добавлены другим subdirectory, второй раз их не добавляем.
if(NOT TARGET json_lib)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../serv/json ${CMAKE_CURRENT_BINARY_DIR}/json)
endif()

if(NOT TARGET sql_lib)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../serv/sqlite ${CMAKE_CURRENT_BINARY_DIR}/sqlite)
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if(WIN32)
    target_link_libraries(serv_coroutine_lib
        PUBLIC
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
        PRIVATE
            sql_lib
            json_lib
            ws2_32
    )
else()
    target_link_libraries(serv_coroutine_lib
        PUBLIC
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
        PRIVATE
            sql_lib
            json_lib
    )
endif()
