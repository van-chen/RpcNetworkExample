#include "AuthError.h"
#include <Windows.h>

BH::AuthError::AuthError(const std::wstring& text, unsigned int code)
    :_errorText(text)
{
    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

    _errorText += L" " + std::wstring(messageBuffer, size);
    LocalFree(messageBuffer);
}

const wchar_t* BH::AuthError::What()
{
    return _errorText.c_str();
}

BH::AuthError::AuthError(const std::wstring& text)
    :_errorText(text)
{
}

BH::AuthError::AuthError(unsigned int code)
{
    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

    _errorText += std::wstring(messageBuffer, size);
    LocalFree(messageBuffer);
}

BH::AuthError::~AuthError()
{
}
