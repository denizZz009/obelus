#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <bits.h>

class BitsSimulator {
public:
    static void RunAnalysis(); // Renamed from RunSimulation for consistency

private:
     static std::vector<unsigned char> simulatedPayload;
};
