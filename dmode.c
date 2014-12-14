#ifndef SUCCESS
#define SUCCESS 0
#endif
#ifndef FAILURE
#define FAILURE 1
#endif

// DebugMode (BOOL)
// activates the debug mode for the current process 
// requires the privilege to be 'ENABLED'
// returns FAILURE on failure, and SUCCESS on success

int DebugMode(BOOL bToggle) {
    HANDLE hToken;
    DWORD cbTokPriv = sizeof (TOKEN_PRIVILEGES);
    static TOKEN_PRIVILEGES tpGodModeActivated, tpOriginalMode;

    if (bToggle) {
        tpGodModeActivated.PrivilegeCount = 1;
        tpGodModeActivated.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tpGodModeActivated.Privileges[0].Luid);

        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            return FAILURE;
        }

        if (!AdjustTokenPrivileges(hToken, FALSE, &tpGodModeActivated, sizeof (tpGodModeActivated),
                &tpOriginalMode, &cbTokPriv) != ERROR_SUCCESS) {
            CloseHandle(hToken);
            return FAILURE;
        }
        CloseHandle(hToken);
    }
    else {

        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            return FAILURE;
        }
        if (AdjustTokenPrivileges(hToken, FALSE, &tpOriginalMode, sizeof (tpOriginalMode), NULL, NULL)
                != ERROR_SUCCESS) {
            CloseHandle(hToken);
            return FAILURE;
        }

    }

    return SUCCESS;
}
