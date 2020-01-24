// RPC.cpp : Defines the entry point for the application.
//

#include <Windows.h>
#include <iostream>
#include "AuthLib/RPCClient.h"

using namespace std;

std::wstring StringToWstring(const std::string& ansiString)
{
	std::wstring returnValue;
	auto wideCharSize = MultiByteToWideChar(CP_UTF8, 0, ansiString.c_str(), -1, nullptr, 0);
	if (wideCharSize == 0)
	{
		return returnValue;
	}
	returnValue.resize(wideCharSize);
	wideCharSize = MultiByteToWideChar(CP_UTF8, 0, ansiString.c_str(), -1, &returnValue[0], wideCharSize);
	if (wideCharSize == 0)
	{
		returnValue.resize(0);
		return returnValue;
	}
	returnValue.resize(wideCharSize - 1);
	return returnValue;
}

int main(int argc, char* argv[])
{
	try
	{
		std::wstring netAddress{ L"127.0.0.1" };
		if (argc > 1)
			netAddress = StringToWstring(argv[1]);
		BH::RPC::Client client(L"BHTEST", netAddress, L"55313");
		client.SetLog(
			[](auto mes)
			{
				std::wcout << mes.c_str() << std::endl;
			});
		client.Connect();
		client.Auth(L"hello!");
		client.Stop();
	}
	catch (BH::AuthError & error)
	{
		//MessageBox(nullptr, error.What(), L"Error", MB_OK);
		std::wcout << error.What() << std::endl;
	}

	system("pause");
}
