#include "RPCClient.h"
#include <Windows.h>
#include <ntdsapi.h>
#include "bhcredcheck.h"

BH::RPC::Client::Client(const std::wstring& name, const std::wstring& networkAddress, const std::wstring& endPoint)
    :_name(name),_pszNetworkAddress(networkAddress), _endpoint(endPoint)
{
}

BH::RPC::Client::~Client()
{
    Stop();
}

void BH::RPC::Client::Connect()
{
    if (_isStarted)
        return;

    RPC_STATUS status;
    RPC_SECURITY_QOS SecQos;

    // Use a convenience function to concatenate the elements of
    // the string binding into the proper sequence.
    status = RpcStringBindingCompose(
        nullptr,
        (RPC_WSTR)_pszProtocolSequence.c_str(),
        (RPC_WSTR)_pszNetworkAddress.c_str(),
        (RPC_WSTR)_endpoint.c_str(),
        nullptr,
        &_pszStringBinding);
    Log(L"RpcStringBindingCompose returned 0x%x", status);
    Log(L"pszStringBinding = %s", _pszStringBinding);
    if (status) {
        throw AuthError(L"Ошибка преобразования строк.", status);
    }

    // Set the binding handle that will be used to bind to the server.
    status = RpcBindingFromStringBinding(_pszStringBinding,
        &bhcredcheck_v1_0_c_ifspec);
    Log(L"RpcBindingFromStringBinding returned 0x%x", status);
    if (status) {
        throw AuthError(L"Не удалось привязать интерфейс.", status);
    }

    _spn = MakeSpn(_name);

    Log(L"Spn 0x%s", _spn.c_str());

    // Set the quality of service on the binding handle
    SecQos.Version = RPC_C_SECURITY_QOS_VERSION_1;
    SecQos.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
    SecQos.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
    SecQos.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;

    // Set the security provider on binding handle
    status = RpcBindingSetAuthInfoEx(bhcredcheck_v1_0_c_ifspec,
        (RPC_WSTR)_spn.c_str(),
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL,
        RPC_C_AUTHZ_NONE,
        &SecQos);

    Log(L"RpcBindingSetAuthInfoEx returned 0x%x", status);
    if (status) {
        throw AuthError(L"Не удалось задать параметры аутентийикации.", status);
    }
}

void BH::RPC::Client::Stop()
{
    if (_isStarted)
    {
        auto status = RpcStringFree(&_pszStringBinding);  // remote calls done; unbind
        Log(L"RpcStringFree returned 0x%x", status);

        status = RpcBindingFree(&bhcredcheck_v1_0_c_ifspec);  // remote calls done; unbind
        Log(L"RpcBindingFree returned 0x%x\n", status);
    }
    _isStarted = false;
}

void BH::RPC::Client::SetLog(std::function<void(const std::wstring&)> log)
{
    _log = log;
}

bool BH::RPC::Client::Auth(const std::wstring& mes)
{
    if (!_isStarted)
        throw AuthError(L"Клиент не подключен к серверу");

    Log(L"Calling the remote procedure 'HelloProc'");

    RpcTryExcept{
        CheckAuth(bhcredcheck_v1_0_c_ifspec,mes.c_str());  // make call with user message
    }
        RpcExcept((((RpcExceptionCode() != STATUS_ACCESS_VIOLATION) &&
        (RpcExceptionCode() != STATUS_DATATYPE_MISALIGNMENT) &&
            (RpcExceptionCode() != STATUS_PRIVILEGED_INSTRUCTION) &&
            (RpcExceptionCode() != STATUS_BREAKPOINT) &&
            (RpcExceptionCode() != STATUS_STACK_OVERFLOW) &&
            (RpcExceptionCode() != STATUS_IN_PAGE_ERROR) &&
            (RpcExceptionCode() != STATUS_GUARD_PAGE_VIOLATION)
            )
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)) {
        auto ulCode = RpcExceptionCode();
        Log(L"Runtime reported exception 0x%lx = %ld\n", ulCode, ulCode);
        return false;
    }
    RpcEndExcept;
    return true;
}

void BH::RPC::Client::Log(const wchar_t* format, ...)
{
    wchar_t buffer[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(buffer, format, args);
    va_end(args);
    if (_log)
        _log(buffer);
}

std::wstring BH::RPC::Client::MakeSpn(const std::wstring& name)
{
    DWORD status = ERROR_SUCCESS;
    wchar_t** arrSpn = NULL;
    DWORD ulSpn{ 0 };
    status = DsGetSpn(DS_SPN_NB_HOST,
        name.c_str(),
        NULL, // DN of this service.
        0, // Use the default instance port.
        0, // Number of additional instance names.
        NULL, // No additional instance names.
        NULL, // No additional instance ports.
        &ulSpn, // Size of SPN array.
        &arrSpn); // Returned SPN(s).	
    if (status != ERROR_SUCCESS || 0 == ulSpn) {
        throw BH::AuthError(L"Error creating spn.", status);
    }

    return std::wstring(*arrSpn);
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
    return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
    free(ptr);
}