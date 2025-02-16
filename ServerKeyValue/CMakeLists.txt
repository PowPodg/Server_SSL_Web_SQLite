cmake_minimum_required (VERSION 3.22)
project ("Serv_test" LANGUAGES C CXX )

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  pqxx
  GIT_REPOSITORY https://github.com/jtv/libpqxx.git
  GIT_TAG master 
)
FetchContent_MakeAvailable(pqxx)

find_package(Boost REQUIRED COMPONENTS asio system json)
add_executable(${PROJECT_NAME} "ServMain.cpp" "ServerKeyValue/ServerKeyValue.cpp") 
if(WIN32)
target_link_libraries(${PROJECT_NAME} PRIVATE Boost::asio Boost::system ws2_32 Boost::json pqxx)
else()
target_link_libraries(${PROJECT_NAME} PRIVATE Boost::asio Boost::system Boost::json pqxx)
endif()
target_include_directories(${PROJECT_NAME} PRIVATE ${Boost_INCLUDE_DIRS})

