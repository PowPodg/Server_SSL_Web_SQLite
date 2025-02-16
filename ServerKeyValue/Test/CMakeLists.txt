cmake_minimum_required(VERSION 3.22)
project(ServTest)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(FetchContent)
FetchContent_Declare(
  pqxx
  GIT_REPOSITORY https://github.com/jtv/libpqxx.git
  GIT_TAG master 
)
FetchContent_MakeAvailable(pqxx)
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.8.0  
)
FetchContent_MakeAvailable(Catch2)
find_package(Boost REQUIRED COMPONENTS asio system json)
add_executable(test_srv test_serv.cpp "../ServerKeyValue/ServerKeyValue.cpp")  # Тестовый файл
if(WIN32)
target_link_libraries(test_srv PRIVATE Catch2::Catch2WithMain Boost::asio Boost::system ws2_32 Boost::json pqxx)
else()
target_link_libraries(test_srv PRIVATE Catch2::Catch2WithMain Boost::asio Boost::system Boost::json pqxx)
endif()
include(CTest)
add_test(NAME TestSERVER COMMAND test_srv)