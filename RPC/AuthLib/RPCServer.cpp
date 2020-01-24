#include "RPCServer.h"
#include <Windows.h>
#include <ntdsapi.h>
#include "bhcredcheck.h"
#include <memory>

BH::RPC::Server::Server(const std::wstring& name, const std::wstring& endPoint)
    :_name(name), _endpoint(endPoint)
{
}

BH::RPC::Server::~Server()
{
    Stop();
}

void BH::RPC::Server::StartListen()
{
    if (_isListening)
        return;

    auto isStarted = std::make_shared < std::promise<bool> >();
    _hExec = std::thread(&BH::RPC::Server::Exec, this, isStarted);
    isStarted->get_future().get();
}

void BH::RPC::Server::Stop()
{
    if (!_isListening)
        return;

    RPC_STATUS status;

    Log(L"Calling RpcMgmtStopServerListening");
    status = RpcMgmtStopServerListening(NULL);
    Log(L"RpcMgmtStopServerListening returned: 0x%x", status);

    Log(L"Calling RpcServerUnregisterIf");
    status = RpcServerUnregisterIf(NULL, NULL, FALSE);
    Log(L"RpcServerUnregisterIf returned 0x%x", status);

    if (_hExec.joinable())
        _hExec.join();
    _isListening = false;
}

void BH::RPC::Server::SetLog(std::function<void(const std::wstring&)> log)
{
    _log = log;
}

void BH::RPC::Server::Log(const wchar_t* format, ...)
{
    wchar_t buffer[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(buffer, format, args);
    va_end(args);
    if (_log)
        _log(buffer);
}

std::wstring BH::RPC::Server::MakeSpn(const std::wstring& name)
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

void BH::RPC::Server::Exec(std::shared_ptr<std::promise<bool>> isStarted)
{
    Log(L"Start listening...");
    RPC_STATUS status;
    char* pszSecurity = NULL;

    status = RpcServerUseProtseqEp((RPC_WSTR)_pszProtocolSequence.c_str(),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_WSTR)_endpoint.c_str(),
        pszSecurity);  // Security descriptor
    Log(L"RpcServerUseProtseqEp returned 0x%x", status);
    if (status) {
        throw AuthError(L"Не удалось открыть канал.", status);
    }

    _spn = MakeSpn(_name);

    Log(L"Spn %s", _spn.c_str());

    // Using Negotiate as security provider.
    status = RpcServerRegisterAuthInfo((RPC_WSTR)_spn.c_str(),
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL,
        NULL);

    Log(L"RpcServerRegisterAuthInfo returned 0x%x", status);
    if (status) {
        throw(L"Не удалось выполнить аутентификацию.", status);
    }

    status = RpcServerRegisterIfEx(bhcredcheck_v1_0_s_ifspec, NULL, NULL, RPC_IF_ALLOW_SECURE_ONLY, RPC_C_LISTEN_MAX_CALLS_DEFAULT, NULL);

    Log(L"RpcServerRegisterIfEx returned 0x%x", status);

    if (status) {
        throw(L"Не удалось зарегестрировать сервер.", status);
	}

	Log(L"Calling RpcServerListen");
	status = RpcServerListen(_cMinCalls,
		RPC_C_LISTEN_MAX_CALLS_DEFAULT,
		TRUE);
	Log(L"RpcServerListen returned: 0x%x", status);
	if (status) {
		throw AuthError(L"Не удалось запустить сервер.", status);
	}

	Log(L"Calling RpcMgmtWaitServerListen");
    _isListening.store(true);
    isStarted->set_value(true);
	status = RpcMgmtWaitServerListen();  // wait operation
	Log(L"RpcMgmtWaitServerListen returned: 0x%x", status);
}


void CheckAuth(IN RPC_BINDING_HANDLE hBinding, const wchar_t* pszString)
{
    //printf_s("%s\n", pszString);
    if (RPC_S_OK == RpcImpersonateClient(hBinding))
    {
        BH::RPC::SuccessfulAuth(pszString);
        RpcRevertToSelf();
    }
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
    return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
    free(ptr);
}