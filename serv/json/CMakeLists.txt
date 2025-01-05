cmake_minimum_required (VERSION 3.22)
project(json_lib)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB INCLUDE_FILES "json/*.h")
install(FILES
    ${INCLUDE_FILES}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/json)

file (GLOB CPPM "*.cpp" HM "*.h")

add_library(json_lib ${CPPM} ${HM})

target_include_directories(json_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})






