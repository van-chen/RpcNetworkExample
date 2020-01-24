# CMakeList.txt : CMake project for RPC, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

add_subdirectory("AuthLib")

add_definitions(-DUNICODE)

add_executable (RPCServer "Server.cpp")

add_executable (RPCClient "Client.cpp")

target_link_libraries(RPCServer AuthLib)

target_link_libraries(RPCClient AuthLibClient)

# TODO: Add tests and install targets if needed.
