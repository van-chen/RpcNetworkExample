// RPC.cpp : Defines the entry point for the application.
//

#include <Windows.h>
#include "Server.h"
#include "spn.h"
#include "bhcredcheck.h"

using namespace std;

#define PURPOSE \
"This Microsoft RPC Version sample program demonstrates\n\
the use of the [string] attribute. For more information\n\
about the attributes and the RPC API functions, see the\n\
RPC programming guide and reference.\n\n"

void Usage(char* pszProgramName)
{
    fprintf_s(stderr, "%s", PURPOSE);
    fprintf_s(stderr, "Usage:  %s\n", pszProgramName);
    fprintf_s(stderr, " -p protocol_sequence\n");
    fprintf_s(stderr, " -e endpoint\n");
    fprintf_s(stderr, " -a server principal name\n");
    fprintf_s(stderr, " -m maxcalls\n");
    fprintf_s(stderr, " -n mincalls\n");
    fprintf_s(stderr, " -f flag_wait_op\n");


    exit(1);
}

int main(int argc, char* argv[])
{
    RPC_STATUS status;
    char* pszProtocolSequence = "ncacn_ip_tcp";
    char* pszSecurity = NULL;
    char* pszEndpoint = "51723";
    char* pszSpn = NULL;
    unsigned int    cMinCalls = 1;
    unsigned int    cMaxCalls = 20;
    unsigned int    fDontWait = FALSE;
    int i;

    // allow the user to override settings with command line switches 
    for (i = 1; i < argc; i++) {
        if ((*argv[i] == '-') || (*argv[i] == '/')) {
            switch (tolower(*(argv[i] + 1))) {
            case 'p':  // protocol sequence
                pszProtocolSequence = argv[++i];
                break;
            case 'e':
                pszEndpoint = argv[++i];
                break;
            case 'a':
                pszSpn = argv[++i];
                break;
            case 'm':
                cMaxCalls = (unsigned int)atoi(argv[++i]);
                break;
            case 'n':
                cMinCalls = (unsigned int)atoi(argv[++i]);
                break;
            case 'f':
                fDontWait = (unsigned int)atoi(argv[++i]);
                break;

            case 'h':
            case '?':
            default:
                Usage(argv[0]);
            }
        }
        else
            Usage(argv[0]);
    }

    status = RpcServerUseProtseqEp((unsigned char*)pszProtocolSequence,
        cMaxCalls,
        (unsigned char*)pszEndpoint,
        pszSecurity);  // Security descriptor
    printf_s("RpcServerUseProtseqEp returned 0x%x\n", status);
    if (status) {
        exit(status);
    }

    // User did not specify spn, construct one.
    if (pszSpn == NULL) {
        MakeSpn(&pszSpn);
    }

    printf_s("RpcServerUseProtseqEp returned %s\n", pszSpn);

    // Using Negotiate as security provider.
    status = RpcServerRegisterAuthInfo((unsigned char*)pszSpn,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL,
        NULL);

    printf_s("RpcServerRegisterAuthInfo returned 0x%x\n", status);
    if (status) {
        exit(status);
    }

    status = RpcServerRegisterIfEx(bhcredcheck_v1_0_s_ifspec, NULL, NULL, 0, RPC_C_LISTEN_MAX_CALLS_DEFAULT, NULL);

    printf_s("RpcServerRegisterIfEx returned 0x%x\n", status);

    if (status) {
        exit(status);
    }

    printf_s("Calling RpcServerListen\n");
    status = RpcServerListen(cMinCalls,
        cMaxCalls,
        fDontWait);
    printf_s("RpcServerListen returned: 0x%x\n", status);
    if (status) {
        exit(status);
    }

    if (fDontWait) {
        printf_s("Calling RpcMgmtWaitServerListen\n");
        status = RpcMgmtWaitServerListen();  // wait operation
        printf_s("RpcMgmtWaitServerListen returned: 0x%x\n", status);
        if (status) {
            exit(status);
        }
    }
	return 0;
}

void HelloProc(IN RPC_BINDING_HANDLE hBinding, char* pszString)
{
    printf_s("%s\n", pszString);
    if (RPC_S_OK == RpcImpersonateClient(hBinding))
    {
        char name[10024];
        DWORD size = 10024;
        GetUserName(name, &size);
        printf_s("Impersonate ok %s\n", name);
        RpcRevertToSelf();
    }
    else
        printf_s("Impersonate fail\n");
}

void Shutdown(IN RPC_BINDING_HANDLE hBinding)
{
    RPC_STATUS status;

    printf_s("Calling RpcMgmtStopServerListening\n");
    status = RpcMgmtStopServerListening(NULL);
    printf_s("RpcMgmtStopServerListening returned: 0x%x\n", status);
    if (status) {
        exit(status);
    }

    printf_s("Calling RpcServerUnregisterIf\n");
    status = RpcServerUnregisterIf(NULL, NULL, FALSE);
    printf_s("RpcServerUnregisterIf returned 0x%x\n", status);
    if (status) {
        exit(status);
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