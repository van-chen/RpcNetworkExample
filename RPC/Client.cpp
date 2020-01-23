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
    unsigned char* pszUuid = NULL;
    unsigned char* pszProtocolSequence = (unsigned char*)"ncacn_ip_tcp";
    unsigned char* pszNetworkAddress = NULL;
    unsigned char* pszEndpoint = (unsigned char*)"51723";
    char* pszSpn = NULL;
    unsigned char* pszOptions = NULL;
    unsigned char* pszStringBinding = NULL;
    char* pszString = "hello, world";
    RPC_SECURITY_QOS SecQos;
    unsigned long ulCode;
    int i;

    // allow the user to override settings with command line switches
    for (i = 1; i < argc; i++) {
        if ((*argv[i] == '-') || (*argv[i] == '/')) {
            switch (tolower(*(argv[i] + 1))) {
            case 'p':  // protocol sequence
                pszProtocolSequence = (unsigned char*)argv[++i];
                break;
            case 'n':  // network address
                pszNetworkAddress = (unsigned char*)argv[++i];
                break;
            case 'e':  // endpoint
                pszEndpoint = (unsigned char*)argv[++i];
                break;
            case 'a':
                pszSpn = argv[++i];
                break;
            case 'o':
                pszOptions = (unsigned char*)argv[++i];
                break;
            case 's':
                pszString = argv[++i];
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

    // Use a convenience function to concatenate the elements of
    // the string binding into the proper sequence.
    status = RpcStringBindingCompose(pszUuid,
        pszProtocolSequence,
        pszNetworkAddress,
        pszEndpoint,
        pszOptions,
        &pszStringBinding);
    printf_s("RpcStringBindingCompose returned 0x%x\n", status);
    printf_s("pszStringBinding = %s\n", pszStringBinding);
    if (status) {
        exit(status);
    }

    // Set the binding handle that will be used to bind to the server.
    status = RpcBindingFromStringBinding(pszStringBinding,
        &bhcredcheck_v1_0_c_ifspec);
    printf_s("RpcBindingFromStringBinding returned 0x%x\n", status);
    if (status) {
        exit(status);
    }

    // User did not specify spn, construct one.
    if (pszSpn == NULL) {
        MakeSpn(&pszSpn);
    }

    printf_s("Spn 0x%s\n", pszSpn);

    // Set the quality of service on the binding handle
    SecQos.Version = RPC_C_SECURITY_QOS_VERSION_1;
    SecQos.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
    SecQos.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
    SecQos.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;

    // Set the security provider on binding handle
    status = RpcBindingSetAuthInfoEx(bhcredcheck_v1_0_c_ifspec,
        (unsigned char*)pszSpn,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL,
        RPC_C_AUTHZ_NONE,
        &SecQos);

    printf_s("RpcBindingSetAuthInfoEx returned 0x%x\n", status);
    if (status) {
        exit(status);
    }

    printf_s("Calling the remote procedure 'HelloProc'\n");
    printf_s("Print the string '%s' on the server\n", pszString);

    RpcTryExcept{
        HelloProc(bhcredcheck_v1_0_c_ifspec,pszString);  // make call with user message
        printf_s("Calling the remote procedure 'Shutdown'\n");
        Shutdown(bhcredcheck_v1_0_c_ifspec);  // shut down the server side
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
        ulCode = RpcExceptionCode();
        printf_s("Runtime reported exception 0x%lx = %ld\n", ulCode, ulCode);


    }
    RpcEndExcept

        //  The calls to the remote procedures are complete.
        //  Free the string and the binding handle
        status = RpcStringFree(&pszStringBinding);  // remote calls done; unbind
    printf_s("RpcStringFree returned 0x%x\n", status);
    if (status) {
        exit(status);
    }

    status = RpcBindingFree(&bhcredcheck_v1_0_c_ifspec);  // remote calls done; unbind
    printf_s("RpcBindingFree returned 0x%x\n", status);
    if (status) {
        exit(status);
    }

    exit(0);
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
    return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
    free(ptr);
}