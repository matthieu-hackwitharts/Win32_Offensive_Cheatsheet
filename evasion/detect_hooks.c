// https://github.com/xforcered/Detect-Hooks/blob/main/src/detect-hooks.c

#include <windows.h>
#include <stdio.h>

void main(char* args, int length) {

    char* returnData = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65535);
    memset(returnData, 0, 65535);
    unsigned int returnDataLen;
    PDWORD functionAddress = (PDWORD)0;


    HMODULE libraryBase = LoadLibrary("ntdll.dll");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++) {

        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char* functionName = (char*)functionNameVA;

        DWORD_PTR functionAddressRVA = 0;
        functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
        functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

        char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

        if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0) {
            if (strncmp(functionName, (char*)"NtGetTickCount", 14) == 0 ||
                strncmp(functionName, (char*)"NtQuerySystemTime", 17) == 0 ||
                strncmp(functionName, (char*)"NtdllDefWindowProc_A", 20) == 0 ||
                strncmp(functionName, (char*)"NtdllDefWindowProc_W", 20) == 0 ||
                strncmp(functionName, (char*)"NtdllDialogWndProc_A", 20) == 0 ||
                strncmp(functionName, (char*)"NtdllDialogWndProc_W", 20) == 0 ||
                strncmp(functionName, (char*)"ZwQuerySystemTime", 17) == 0) { }
            else {
                if (memcmp(functionAddress, syscallPrologue, 4) != 0) {
                    returnDataLen = _snprintf_s(NULL, 0, "%s\n", functionName);
                    _snprintf_s(returnData + strlen(returnData), returnDataLen + 1, "%s\n", functionName);
                }
            }
        }
    }
}
