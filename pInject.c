// pInject;
// contains functions related to process injection
// namely pInject ( DWORD dwPid, void* startAddress, DWORD dwAdditionalInfo)
// startAddress. Now that's a tough one !
// we will need to rebase that as well

// TODO:
// also fix IAT and other issues with relocatable code
// not a problem unless dlls are loaded in different places to in our address space
// if this is a problem (and this code hasn't been updated. now=9/6/2006)
// use GetProcAddress (assuming that's in the right place!)


#define PINJECT_SUCCESS 0
#define PINJECT_MEM_ERR -1
#define PINJECT_RELOC_ERR -2
#define PINJECT_PROC_ACCESS_ERR -3
#define PINJECT_NO_RELOC -4

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr) + (addValue) ) 
// http://www.codeproject.com/dll/DLL_Injection_tutorial.asp
// actually from a book by matt pietrek and whored out over the internet

int pInject(HANDLE hModule, DWORD dwInPid, void* pStartAddr, DWORD dwParam) {
    HANDLE hOtherProcess;
    void *pNewModule, *pModuleAsData, *pBaseForRVA;
    WORD *wRelocRVAs;
    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_BASE_RELOCATION pBaseReloc;

    unsigned int i = 0, j = 0, nRelCount = 0, offset;
    DWORD dwModSiz, dwWritten = 0, dwMemDelta, dwBaseRelocSiz, *pAbsoluteRelocAddr, dwRelocSecOffset;

    // open the process
    hOtherProcess = OpenProcess(PROCESS_ALL_ACCESS,
            FALSE,
            dwInPid);

    if (hOtherProcess == NULL) {
        return PINJECT_PROC_ACCESS_ERR; // return process access error
    }

    // get some info on module, such as size
    pDOSHeader = hModule;
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pDOSHeader + pDOSHeader->e_lfanew);
    dwModSiz = pNTHeader->OptionalHeader.SizeOfImage;

    if ((pNTHeader->FileHeader.Characteristics & 0x01) == IMAGE_FILE_RELOCS_STRIPPED) { // check if reloc table stripped
        return PINJECT_NO_RELOC;
    }

    // ask windows nicely to allocate us some memory in the other process
    pNewModule = VirtualAllocEx(hOtherProcess,
            NULL,
            dwModSiz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    if (pNewModule == NULL) {// we couldn't alloc the mem in the other process
        return PINJECT_MEM_ERR;
    }

    // now we have a module in our address space and an address to memory in the other 
    // address space. before we copy it over; it needs rebasing
    // in order to not murder the original module - we'll have to make a copy
    // and rebase that

    pModuleAsData = HeapAlloc(GetProcessHeap(),
            HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY,
            dwModSiz);

    CopyMemory(pModuleAsData,
            hModule,
            dwModSiz);

    // now, to rebase module at pModuleAsData

    pDOSHeader = pModuleAsData;
    pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDOSHeader, pDOSHeader->e_lfanew);

    dwMemDelta = (DWORD) pNewModule - pNTHeader->OptionalHeader.ImageBase;

    dwRelocSecOffset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    pBaseReloc = MakePtr(PIMAGE_BASE_RELOCATION, pModuleAsData, dwRelocSecOffset); // absolute pointer to reloc section

    dwBaseRelocSiz = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    while (j < dwBaseRelocSiz) {
        // this loop runs through all the blocks
        // which correspond to relocations in successive pages
        j += pBaseReloc->SizeOfBlock;

        nRelCount = (pBaseReloc->SizeOfBlock - sizeof (IMAGE_BASE_RELOCATION)) / sizeof (WORD);
        pBaseForRVA = MakePtr(LPVOID, pModuleAsData, pBaseReloc->VirtualAddress);
        wRelocRVAs = MakePtr(LPWORD, pBaseReloc, sizeof (IMAGE_BASE_RELOCATION));

        for (i = 0; i < nRelCount; i++) {// and this one runs through the entries for each page and fixes-em-up

            switch (wRelocRVAs[i] >> 12) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    continue; // we ignore these; used for padding
                case IMAGE_REL_BASED_HIGHLOW:
                    // now is where we do are fixing
                    offset = wRelocRVAs[i] & 0x0FFF; // bit masking
                    pAbsoluteRelocAddr = MakePtr(DWORD*, pBaseForRVA, offset);
                    // pAbsoluteRelocAddr as you might imagine is the absolute address to add delta to
                    *pAbsoluteRelocAddr += dwMemDelta; // fix it up
                    break;
                default:
                    return PINJECT_RELOC_ERR;
            }

        } //end for
        pBaseReloc = MakePtr(PIMAGE_BASE_RELOCATION, pBaseReloc, pBaseReloc->SizeOfBlock);
    }

    pNTHeader->OptionalHeader.ImageBase = (DWORD) pNewModule;

    // finished relocating
    // copy pModuleAsData to pNewModule in other address space

    WriteProcessMemory(hOtherProcess,
            pNewModule,
            pModuleAsData,
            dwModSiz,
            &dwWritten);

    if (dwWritten != dwModSiz) // to check for error - confirm dwModSiz == dwWritten
    {
        return PINJECT_MEM_ERR;
    }

    // call CreateRemoteThread on rebased startAddr (todo: or fire off baseOfCode?)

    CreateRemoteThread(hOtherProcess,
            0,
            0,
            (LPTHREAD_START_ROUTINE) ((DWORD) pStartAddr - (DWORD) hModule + (DWORD) pNewModule),
            (LPVOID) dwParam,
            0,
            NULL);

    CloseHandle(hOtherProcess);

    return PINJECT_SUCCESS;
}


