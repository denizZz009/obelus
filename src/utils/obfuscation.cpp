#include "obfuscation.h"
#include <winternl.h>
#include "../logger/logger.h"

// Structs definitions needed for PEB walking if not standard
// standard windows.h usually has basic PEB, but LDR_DATA_TABLE_ENTRY might need definition or casting.
// For simplicity assuming standard winternl headers work, else we might need custom structs.

// Custom definitions to ensure access to BaseDllName
typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

namespace Utils {

    HMODULE GetModuleHandleH(DWORD moduleHash) {
#ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
#else
        PPEB peb = (PPEB)__readfsdword(0x30);
#endif
        PMY_PEB_LDR_DATA ldr = (PMY_PEB_LDR_DATA)peb->Ldr;
        PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;

        while (listEntry != listHead) {
            PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(listEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            
            if (entry->BaseDllName.Buffer) {
                DWORD currentHash = 0;
                // Hash BaseDllName (e.g. "kernel32.dll", not full path)
                wchar_t* name = entry->BaseDllName.Buffer;
                while (*name) {
                    wchar_t c = *name;
                    if (c >= L'A' && c <= L'Z') c += 32;
                    currentHash = _rotr(currentHash, 13);
                    currentHash += c;
                    name++;
                }

                if (currentHash == moduleHash) {
                    return (HMODULE)entry->DllBase;
                }
            }
            listEntry = listEntry->Flink;
        }
        return NULL;
    }

    FARPROC GetProcAddressH(HMODULE hModule, DWORD procHash) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* names = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            char* name = (char*)((BYTE*)hModule + names[i]);
            if (HashString(name) == procHash) {
                return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
            }
        }
        return NULL;
    }

    std::string Deobfuscate(const std::vector<unsigned char>& encrypted, unsigned char key) {
        std::string result;
        result.reserve(encrypted.size());
        for (unsigned char c : encrypted) {
            result.push_back(c ^ key);
        }
        return result;
    }
}
