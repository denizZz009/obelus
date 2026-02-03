#pragma once
#include <windows.h>
#include <string>

class PersistenceSim {
public:
    static void RunAnalysis();
    
private:
    static void AnalyzeBinary(const std::string& targetBinary);
};
