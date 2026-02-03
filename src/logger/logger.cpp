#include "logger.h"
#include <vector>
#include <iomanip>
#include <sstream>

std::mutex Logger::logMutex;

void Logger::Log(LogLevel level, const std::string& msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    WORD originalAttrs = consoleInfo.wAttributes;

    SetConsoleTextAttribute(hConsole, GetLevelColor(level));
    std::cout << "[" << GetLevelStr(level) << "] ";
    
    SetConsoleTextAttribute(hConsole, originalAttrs);
    std::cout << msg << std::endl;
}

void Logger::HexDump(const void* data, size_t size, const std::string& label) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::cout << "[HEX] " << label << " (" << size << " bytes):" << std::endl;
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)p[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
}

std::string Logger::GetLevelStr(LogLevel level) {
    switch(level) {
        case LogLevel::INFO: return "+";
        case LogLevel::WARN: return "!";
        case LogLevel::ERR: return "-";
        case LogLevel::SUCCESS: return "*";
        case LogLevel::TRACE: return "~";
        default: return "?";
    }
}

WORD Logger::GetLevelColor(LogLevel level) {
    switch(level) {
        case LogLevel::INFO: return FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Cyan
        case LogLevel::WARN: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Yellow
        case LogLevel::ERR: return FOREGROUND_RED | FOREGROUND_INTENSITY; // Red
        case LogLevel::SUCCESS: return FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Green
        case LogLevel::TRACE: return FOREGROUND_INTENSITY; // Gray
        default: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}
