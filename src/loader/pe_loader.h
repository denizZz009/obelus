#pragma once
#include <windows.h>

class PELoader {
public:
    // Performs reflective loading of a PE from a memory buffer
    static void RunReflectiveLoader(void* peBase);

private:
    static PIMAGE_NT_HEADERS GetHeaders(void* base);
    static void MapSections(void* base, PIMAGE_NT_HEADERS ntHdrs);
    static void ResolveImports(void* base, PIMAGE_NT_HEADERS ntHdrs);
    static void ApplyRelocations(void* base, PIMAGE_NT_HEADERS ntHdrs);
};
