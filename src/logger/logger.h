#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <mutex>

enum class LogLevel {
    INFO,
    WARN,
    ERR,
    SUCCESS,
    TRACE
};

class Logger {
public:
    static void Log(LogLevel level, const std::string& msg);
    static void HexDump(const void* data, size_t size, const std::string& label);

private:
    static std::string GetLevelStr(LogLevel level);
    static WORD GetLevelColor(LogLevel level);
    static std::mutex logMutex;
};

#define LOG_INFO(msg) Logger::Log(LogLevel::INFO, msg)
#define LOG_WARN(msg) Logger::Log(LogLevel::WARN, msg)
#define LOG_ERROR(msg) Logger::Log(LogLevel::ERR, msg)
#define LOG_SUCCESS(msg) Logger::Log(LogLevel::SUCCESS, msg)
#define LOG_TRACE(msg) Logger::Log(LogLevel::TRACE, msg)
