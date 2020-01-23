# CMakeList.txt : CMake project for RPC, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

add_definitions(-DSECURITY_WIN32)
# Add source to this project's executable.
add_executable (RPCServer "Server.cpp" "Server.h" "bhcredcheck.h" "bhcredcheck_s.c" "spn.cpp" "spn.h" )

add_executable (RPCClient "Client.cpp" "Client.h" "bhcredcheck.h" "bhcredcheck_c.c" "spn.cpp" "spn.h" )

target_link_libraries(RPCServer "Ntdsapi.lib" "Rpcrt4.lib" "NetApi32.lib")

target_link_libraries(RPCClient "Ntdsapi.lib" "Rpcrt4.lib" "NetApi32.lib")

# TODO: Add tests and install targets if needed.
