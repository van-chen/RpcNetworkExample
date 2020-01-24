// RPC.cpp : Defines the entry point for the application.
//

#include <Windows.h>
#include <iostream>
#include "AuthLib/RPCServer.h"

using namespace std;

void BH::RPC::SuccessfulAuth(const std::wstring& mes)
{
	wchar_t name[1024];
    DWORD size = 1024;
    GetUserName(name, &size);
	std::wcout <<std::endl << name << L": " << mes.c_str() << std::endl;;
}

int main(int argc, char* argv[])
{
	try
	{
		BH::RPC::Server Server(L"BHTEST", L"55313");
		Server.SetLog(
			[](auto mes)
			{
				std::wcout << mes << std::endl;
			});
		Server.StartListen();
		system("pause");
		Server.Stop();
	}
	catch (BH::AuthError & error)
	{
		std::wcout << error.What();
	}

	system("pause");

	return 0;
}


