# CMakeList.txt : CMake project for RPC, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

add_definitions(-DSECURITY_WIN32 -DUNICODE -DRPC_USE_NATIVE_WCHAR -D_NATIVE_WCHAR_T_DEFINED)

add_library(AuthLibClient 
"Auth.h" 
"Auth.cpp" 
"bhcredcheck.h" 
"bhcredcheck_c.c"
"RPCClient.h"
"RPCClient.cpp"
"AuthError.h"
"AuthError.cpp"
)

add_library(AuthLib 
"Auth.h" 
"Auth.cpp" 
"bhcredcheck.h" 
"bhcredcheck_s.c"
"RPCServer.h" 
"RPCServer.cpp"
"AuthError.h"
"AuthError.cpp"
)
target_link_libraries(AuthLib "Ntdsapi.lib" "Rpcrt4.lib" "NetApi32.lib")
target_link_libraries(AuthLibClient "Ntdsapi.lib" "Rpcrt4.lib" "NetApi32.lib")

# TODO: Add tests and install targets if needed.