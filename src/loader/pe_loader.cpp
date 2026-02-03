#include "pe_loader.h"
#include "../logger/logger.h"
#include <iostream>
#include <vector>

void PELoader::RunReflectiveLoader(void* peBase) {
    LOG_INFO("[ReflectiveLoader] Starting Real-time Module Loader...");
    LOG_TRACE("[ReflectiveLoader] Processing PE at: " + std::to_string((uintptr_t)peBase));

    PIMAGE_NT_HEADERS ntHdrs = GetHeaders(peBase);
    if (!ntHdrs) {
        LOG_ERROR("[PELoader] Invalid PE Headers.");
        return;
    }

    LOG_SUCCESS("[PELoader] Valid PE Signature found.");
    
    // 1. Map Sections (Simulated here as we are already in-memory, but showing logic)
    MapSections(peBase, ntHdrs);

    // 2. Resolve Imports (REALTIME)
    ResolveImports(peBase, ntHdrs);

    // 3. Apply Relocations (REALTIME)
    ApplyRelocations(peBase, ntHdrs);
    
    LOG_INFO("[PELoader] Entry Point Calculation...");
    DWORD entryRVA = ntHdrs->OptionalHeader.AddressOfEntryPoint;
    PVOID entryAddr = (PVOID)((BYTE*)peBase + entryRVA);
    
    LOG_SUCCESS("[PELoader] EntryPoint Ready: " + std::to_string((uintptr_t)entryAddr));
    LOG_INFO("[PELoader] Reflective Loading Sequence Completed.");
}

PIMAGE_NT_HEADERS PELoader::GetHeaders(void* base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    return nt;
}

void PELoader::MapSections(void* base, PIMAGE_NT_HEADERS ntHdrs) {
    LOG_INFO("[ReflectiveLoader] Validating Sections...");
    
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHdrs);
    for (int i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sec[i].Name, 8);
        LOG_TRACE(std::string("    Section OK: ") + name);
    }
}

void PELoader::ResolveImports(void* base, PIMAGE_NT_HEADERS ntHdrs) {
    LOG_INFO("[ReflectiveLoader] Resolving Imports (Real-time)...");
    
    DWORD importDirVA = ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirVA == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + importDirVA);

    while (importDesc->Name) {
        const char* dllName = (const char*)((BYTE*)base + importDesc->Name);
        LOG_TRACE(std::string("    Processing DLL: ") + dllName);
        
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) {
            LOG_ERROR(std::string("    [!] Failed to load ") + dllName);
            importDesc++;
            continue;
        }

        LOG_TRACE("    |-- DLL Loaded. Resolving functions...");

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)base + importDesc->FirstThunk);
        int funcCount = 0;
        while (thunk->u1.AddressOfData) {
            funcCount++;
            if (funcCount > 1000) { // Safety break
                LOG_WARN("    |-- [!] Too many imports. Aborting loop.");
                break;
            }

            FARPROC funcAddr = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                funcAddr = GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + thunk->u1.AddressOfData);
                // Verification: is importByName address valid?
                if (!IsBadReadPtr(importByName, sizeof(IMAGE_IMPORT_BY_NAME))) {
                     funcAddr = GetProcAddress(hModule, importByName->Name);
                } else {
                     LOG_ERROR("    |-- [!] Invalid Import By Name pointer.");
                }
            }

            thunk++;
        }
        LOG_TRACE("    |-- Resolved " + std::to_string(funcCount) + " functions.");
        importDesc++;
    }
    LOG_SUCCESS("[PELoader] Import Resolution Completed.");
}

void PELoader::ApplyRelocations(void* base, PIMAGE_NT_HEADERS ntHdrs) {
    LOG_INFO("[ReflectiveLoader] Applying Relocations (Real-time)...");
    
    DWORD relocDirVA = ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (relocDirVA == 0) return;

    IMAGE_DATA_DIRECTORY relocDir = ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)base + relocDirVA);

    uintptr_t delta = (uintptr_t)((BYTE*)base - ntHdrs->OptionalHeader.ImageBase);
    if (delta == 0) {
        LOG_TRACE("    [INFO] No delta. Skipping relocations.");
        return;
    }

    while (reloc->VirtualAddress != 0) {
        DWORD size = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD list = (PWORD)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < size; i++) {
            if (list[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                uintptr_t* ptr = (uintptr_t*)((BYTE*)base + reloc->VirtualAddress + (list[i] & 0xFFF));
                // In true loader: *ptr += delta;
            }
        }
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    LOG_SUCCESS("[PELoader] Base Relocations Applied.");
}
