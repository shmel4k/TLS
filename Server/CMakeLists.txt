cmake_minimum_required(VERSION 2.8)

project(server)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set (LIBS "-lssl -lcrypto -ljsoncpp")

aux_source_directory(src SRCS)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive")

add_executable(${PROJECT_NAME} ${SRCS})

target_link_libraries(${PROJECT_NAME} ${LIBS})
