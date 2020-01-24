#include "Auth.h"
#include <Windows.h>

//std::string Format(const char* format, ...)
//{
//    char buffer[1024];
//    va_list args;
//    va_start(args, format);
//    vsprintf_s(buffer, format, args);
//    va_end(args);
//    return buffer;
//}
//
//std::wstring Format(const wchar_t* format, ...)
//{
//    wchar_t buffer[1024];
//    va_list args;
//    va_start(args, format);
//    vswprintf_s(buffer, format, args);
//    va_end(args);
//    return buffer;
//}

BH::Auth::Auth()
{
}

BH::Auth::~Auth()
{
}

unsigned int BH::Auth::Logon(const std::wstring& userName, const std::wstring& domain, wchar_t* pass)
{
    HANDLE token;
    if (0 != LogonUser(userName.c_str(), domain.c_str(), pass, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token))
    {
        CloseHandle(token);
        return 0;
    }
    return GetLastError();
}

std::wstring BH::Auth::ErrorString(unsigned int error)
{
    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

    std::wstring message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}