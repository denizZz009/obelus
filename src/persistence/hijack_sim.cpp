#include "hijack_sim.h"
#include "../logger/logger.h"
#include <iostream>
#include <vector>
#include <filesystem>
#include <shlobj.h>

namespace fs = std::filesystem;

void PersistenceSim::RunAnalysis() {
    LOG_INFO("[PersistenceSim] Starting Real-time Search Order Hijacking Analysis...");
    
    std::vector<std::string> searchPaths;
    
    // Check common writable/app directories
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        searchPaths.push_back(std::string(path));
    }
    
    const char* programFiles = getenv("ProgramFiles");
    if (programFiles) {
        searchPaths.push_back(std::string(programFiles));
    }

    LOG_TRACE("[PersistenceSim] Scanning paths for potential hijack vectors...");

    for (const auto& root : searchPaths) {
        try {
            if (!fs::exists(root)) continue;

            int limit = 5; // Limit scan depth/count for performance
            for (const auto& entry : fs::recursive_directory_iterator(root)) {
                if (limit <= 0) break;
                
                if (entry.is_regular_file() && entry.path().extension() == ".exe") {
                    AnalyzeBinary(entry.path().string());
                    limit--;
                }
            }
        } catch (...) {
            continue;
        }
    }
}

void PersistenceSim::AnalyzeBinary(const std::string& targetBinary) {
    LOG_INFO("Analyzing Target: " + targetBinary);
    
    // Real-time check: Is there a DLL in the same directory as the EXE?
    // This is the most basic 'Search Order Hijacking' risk.
    fs::path exePath(targetBinary);
    fs::path dir = exePath.parent_path();
    
    try {
        bool foundLocalDll = false;
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".dll") {
                std::string dllName = entry.path().filename().string();
                
                // Check if this DLL also exists in System32 (High Hijack Risk)
                char sys32Path[MAX_PATH];
                GetSystemDirectoryA(sys32Path, MAX_PATH);
                fs::path systemDll = fs::path(sys32Path) / dllName;
                
                if (fs::exists(systemDll)) {
                    LOG_WARN("    [VULN] Potential Hijack Candidate: " + dllName);
                    LOG_WARN("    [FLOW] " + exePath.filename().string() + " might load local " + dllName + " instead of System32 version.");
                    foundLocalDll = true;
                }
            }
        }
        
        if (!foundLocalDll) {
            LOG_TRACE("    [INFO] No immediate local DLL conflicts found.");
        } else {
             Logger::Log(LogLevel::SUCCESS, "[PersistenceSim] Hijack Risk Confirmed in " + exePath.filename().string());
        }
    } catch (...) {
        LOG_ERROR("    [ERROR] Access denied scanning directory.");
    }
}
