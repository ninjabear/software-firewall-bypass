/* exports FindSocketHandles() */

/* REQUIRES windows.h */

#include "FindSocketHandles.h"

tNTQO MyNtQueryObject; // <-- global variables
tNTQSI MyNtQuerySystemInformation; // allowing us to dynamically load NTDLL

BOOL FindNtShit(void) {
    // funct to load up all the NTAPIs we need with the globals above
    MyNtQueryObject = (tNTQO) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryObject");
    if (MyNtQueryObject == NULL) {
        return FALSE;
    }

    MyNtQuerySystemInformation = (tNTQSI) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");
    if (MyNtQuerySystemInformation == NULL) {
        return FALSE;
    }

    return TRUE;
}

int FindPIDsWithSocketHandles(POPEN_SOCK_HANDLE_INFO_EX pOSHIEx, DWORD dwSize, DWORD *dwRequired) {
    // this is the exported deal
    // if dwSize can accomodate all data, pOSHIEx will contain a OPEN_SOCK_HANDLE_INFO_EX struct
    // else cbNeeded will be made to the size required of the function

    POPEN_SOCK_HANDLE_INFO_EX pMyOSHIEx;
    void* pTmpStore; // because realloc can't garantee that data isn't corrupted
    DWORD dwRetBufSiz = 0;
    //
    PSYSTEM_HANDLE_INFORMATION_EX pshiEx;
    HANDLE hProcess, hObj = NULL;
    DWORD cbNeeded = 0, retVal = 0;
    DWORD i = 0, ObjNameCurBufsz = 0, dwWarnCount = 0, dwNextIndex = 0, j = 0;
    POBJECT_NAME_INFORMATION pObjNameInfo;
    BOOL bEntryExists = 0;


    pshiEx = malloc(sizeof (SYSTEM_HANDLE_INFORMATION_EX));
    pMyOSHIEx = malloc(sizeof (OPEN_SOCK_HANDLE_INFO_EX));
    pTmpStore = malloc(sizeof (OPEN_SOCK_HANDLE_INFO_EX));
    dwRetBufSiz = sizeof (OPEN_SOCK_HANDLE_INFO_EX);

    if (pshiEx == NULL || pMyOSHIEx == NULL || pTmpStore == NULL) {
        return FSH_ERROR_NOMEM;
    }

    ZeroMemory(pMyOSHIEx, sizeof (OPEN_SOCK_HANDLE_INFO_EX));

    /* a bit of init */
    FindNtShit();
    //DebugMode(TRUE), in our case we've already done it in main.c
    /* note; if god mode fails, the results will be restricted to processes we have access to */

    MyNtQuerySystemInformation(SystemHandleInformation,
            pshiEx,
            sizeof (SYSTEM_HANDLE_INFORMATION_EX),
            &cbNeeded); //get size for handles

    pshiEx = (PSYSTEM_HANDLE_INFORMATION_EX) realloc(pshiEx, cbNeeded);
    if (pshiEx == NULL) {
        return FSH_ERROR_NOMEM;
    }

    MyNtQuerySystemInformation(SystemHandleInformation,
            pshiEx,
            cbNeeded, // get handles
            &cbNeeded);

    pObjNameInfo = malloc(sizeof (OBJECT_NAME_INFORMATION));
    ObjNameCurBufsz = sizeof (OBJECT_NAME_INFORMATION);

    if (pObjNameInfo == NULL) {
        return FSH_ERROR_NOMEM;
    }

    for (i = 0; i < pshiEx->NumberOfHandles; ++i) {
        // this iterates through enumerated handles
        hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, // irrelevent due to debug mode
                FALSE,
                pshiEx->Information[i].ProcessId);

        if (hProcess != NULL) /* bring their handles into our process space */ {
            if (DuplicateHandle(hProcess,
                    (HANDLE) pshiEx->Information[i].Handle, // mingw ddk declares this as a USHORT
                    GetCurrentProcess(), // and thus the compiler warns us of a cast to 
                    &hObj, // a different size
                    STANDARD_RIGHTS_REQUIRED,
                    FALSE,
                    0) != 0) {
                // get object info
                ZeroMemory(pObjNameInfo, ObjNameCurBufsz);

                retVal = MyNtQueryObject(hObj,
                        ObjectNameInformation,
                        pObjNameInfo,
                        ObjNameCurBufsz,
                        &cbNeeded);

                // i've had issues with this API
                // seems it uses threads and locks itself up sometimes after multiple calls
                // it seems to work to just bosh in a SleepEx to wait, or create a new thread with a timeout            
                // if this does lock itself up, the process becomes unkillable (in my experience :\)

                if (cbNeeded > ObjNameCurBufsz || retVal != 0) {
                    pObjNameInfo = (POBJECT_NAME_INFORMATION) realloc(pObjNameInfo, cbNeeded);

                    if (pObjNameInfo == NULL) {
                        return FSH_ERROR_NOMEM;
                    }

                    ObjNameCurBufsz = cbNeeded;

                    retVal = MyNtQueryObject(hObj,
                            ObjectNameInformation,
                            pObjNameInfo,
                            ObjNameCurBufsz,
                            &cbNeeded);
                }
                // at this point we have enough info to query the driver for info on the connection
                // such as state/endpoint etc
  
                if (lstrcmpW(pObjNameInfo->Name.Buffer, L"\\Device\\Tcp") == 0) {
                    // in our case we don't want to add the same pid twice
                    bEntryExists = 0;
                    for (j = 0; j <= pMyOSHIEx->NumberOfEntries; j++) {
                        if (pMyOSHIEx->OpenSockHandleInfo[j].dwPid == pshiEx->Information[i].ProcessId) {
                            bEntryExists = 1;
                            break;
                        }
                    }
                    if (!bEntryExists) {
                        // add our entry to our local copy of retdata  
                        pTmpStore = realloc(pTmpStore, dwRetBufSiz); // resize ret buffer
                        if (pTmpStore == NULL) {
                            return FSH_ERROR_NOMEM;
                        }

                        CopyMemory(pTmpStore, pMyOSHIEx, dwRetBufSiz);

                        dwRetBufSiz += sizeof (OPEN_SOCK_HANDLE_INFO);

                        pMyOSHIEx = realloc(pMyOSHIEx, dwRetBufSiz);
                        if (pTmpStore == NULL) {
                            return FSH_ERROR_NOMEM;
                        }
                        CopyMemory(pMyOSHIEx, pTmpStore, dwRetBufSiz - sizeof (OPEN_SOCK_HANDLE_INFO));

                        pMyOSHIEx->OpenSockHandleInfo[dwNextIndex].dwPid = pshiEx->Information[i].ProcessId; // fill buff info
                        dwNextIndex++;
                        pMyOSHIEx->NumberOfEntries++;
                    }
                    //done adding entry
                }
            } else {
                dwWarnCount++;
            } // get these alot, they are                              
        }// 5 ERROR_ACCESS_DENIED <bemused face>
        else {
            dwWarnCount++;
        }
        //close handles
        CloseHandle(hObj);
        CloseHandle(hProcess);
    }

    free(pObjNameInfo);
    free(pshiEx);
    free(pTmpStore);


    if (dwSize >= dwRetBufSiz) {
        CopyMemory(pOSHIEx, pMyOSHIEx, dwRetBufSiz);
    } else {
        *dwRequired = dwRetBufSiz;
    }

    free(pMyOSHIEx);

    return dwWarnCount;
}

