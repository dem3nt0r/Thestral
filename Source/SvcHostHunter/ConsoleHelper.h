#pragma once

#include <Windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

enum class ConsoleColor : WORD
{
    Default = 7,

    Black = 0,
    Blue = FOREGROUND_BLUE,
    Green = FOREGROUND_GREEN,
    Red = FOREGROUND_RED,

    Cyan = FOREGROUND_GREEN | FOREGROUND_BLUE,
    Yellow = FOREGROUND_RED | FOREGROUND_GREEN,
    Magenta = FOREGROUND_RED | FOREGROUND_BLUE,
    White = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,

    BrightBlue = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    BrightGreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    BrightRed = FOREGROUND_RED | FOREGROUND_INTENSITY,
    BrightCyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    BrightYellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    BrightMagenta = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    BrightWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
};

class ConsoleHelper
{
public:

    static BOOL InitializeLogFile(const std::wstring& path);

    static void CloseLogFile();

    static void SetColor(ConsoleColor color);

    static void ResetColor();

    static void Print(const wchar_t* format, ...);

    static void PrintColor(ConsoleColor color, const wchar_t* format, ...);

    static void Success(const wchar_t* format, ...);

    static void Error(const wchar_t* format, ...);

    static void Warning(const wchar_t* format, ...);

    static void Info(const wchar_t* format, ...);

private:

    static void VPrint(const wchar_t* format, va_list args);

    static void VPrintColor(ConsoleColor color, const wchar_t* format, va_list args);

    static void Log(const wchar_t* format, va_list args);

    static WORD GetDefaultAttributes();

    static FILE* m_LogFile;
};

class ScopedConsoleColor
{
public:

    explicit ScopedConsoleColor(ConsoleColor color);

    ~ScopedConsoleColor();

private:

    HANDLE m_console = nullptr;

    WORD m_oldAttributes = 7;
};