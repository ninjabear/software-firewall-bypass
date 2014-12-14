
/* you should use these if you're using the mingw ddk
include <ddk\ntapi.h>
include <ddk\ntstatus.h>
 */

// a couple of error codes

#define FSH_ERROR_NONTDLL -1
#define FSH_ERROR_NOMEM -2
#define FSH_ERROR_API -4

//
// if you're not using the mingw ddk !! -------------------------------
//

#define NTSTATUS LONG

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllTypesInformation,
    ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;


#define SystemHandleInformation  16

//
// even if you are  /----------------------------------------
//

// return struct

typedef struct _OPEN_SOCK_HANDLE_INFO {
    DWORD dwPid;
    // we could store some more information in here, if you wanted
} OPEN_SOCK_HANDLE_INFO, *POPEN_SOCK_HANDLE_INFO;

typedef struct _OPEN_SOCK_HANDLE_INFO_EX {
    DWORD NumberOfEntries;
    OPEN_SOCK_HANDLE_INFO OpenSockHandleInfo[1];
} OPEN_SOCK_HANDLE_INFO_EX, *POPEN_SOCK_HANDLE_INFO_EX;

// end of return struct (s)

/* 
    i borrowed these definitions (and the general idea) from some code by a guy called napalm, 
    thanks!
    saved me writing it 
 */

typedef NTSTATUS(WINAPI *tNTQSI)
(DWORD, PVOID, DWORD, PDWORD);

typedef NTSTATUS(WINAPI *tNTQO)
(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, DWORD, PDWORD);

typedef struct _SYSTEM_HANDLE_INFORMATION_EX { // maybe there is something for this in the GPL'd ddk
    ULONG NumberOfHandles; // i've not found it  
    SYSTEM_HANDLE_INFORMATION Information[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
