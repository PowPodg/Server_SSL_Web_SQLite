cmake_minimum_required (VERSION 3.23)

project ("main" LANGUAGES C CXX )
set (_VERSION_MAJOR 0)
set (_VERSION_MINOR 1)

set(CMAKE_CXX_STANDARD 20)

if(WIN32)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
endif()

add_subdirectory(serv)

add_executable (${PROJECT_NAME} "main.cpp" )

target_link_libraries(${PROJECT_NAME} PRIVATE serv_lib)
