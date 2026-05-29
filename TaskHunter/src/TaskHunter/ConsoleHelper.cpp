#include "ConsoleHelper.h"

#include <cstdio>

WORD ConsoleHelper::GetDefaultAttributes() {
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO info{};

    if (GetConsoleScreenBufferInfo(hConsole, &info)) {
        return info.wAttributes;
    }

    return 7;
}

void ConsoleHelper::SetColor(ConsoleColor color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(color));
}

void ConsoleHelper::ResetColor() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), GetDefaultAttributes());
}

void ConsoleHelper::VPrint(const wchar_t* format, va_list args) {
    vwprintf(format, args);
}

// ConsoleHelper::Print(L"Alastor Moody %lu\n", GetCurrentProcessId());
void ConsoleHelper::Print(const wchar_t* format, ...) {

    va_list args;
    va_start(args, format);

    VPrint(format, args);

    va_end(args);
}

// ConsoleHelper::VPrintColor(ConsoleColor::BrightMagenta, L"Hello - %ls\n", L"Alastor Moody");
void ConsoleHelper::VPrintColor(ConsoleColor color, const wchar_t* format, va_list args)
{
    ScopedConsoleColor scope(color);
    vwprintf(format, args);
}

// ConsoleHelper::PrintColor(ConsoleColor::BrightMagenta, L"Hello - %ls\n", L"Alastor Moody");
void ConsoleHelper::PrintColor(ConsoleColor color, const wchar_t* format, ...) {

    va_list args;
    va_start(args, format);

    VPrintColor(color, format, args);

    va_end(args);
}

//ConsoleHelper::Success(L"Hello Alastor Moody\n");
void ConsoleHelper::Success(const wchar_t* format, ...) {

    va_list args;
    va_start(args, format);

    VPrintColor(ConsoleColor::BrightGreen, format, args);

    va_end(args);
}

//ConsoleHelper::Error(L"Hello Alastor Moody\n");
void ConsoleHelper::Error(const wchar_t* format, ...) {
    
    va_list args;
    va_start(args, format);

    VPrintColor(ConsoleColor::BrightRed, format, args);

    va_end(args);
}

//ConsoleHelper::Warning(L"Hello Alastor Moody\n");
void ConsoleHelper::Warning(const wchar_t* format, ...) {

    va_list args;
    va_start(args, format);

    VPrintColor(ConsoleColor::BrightYellow, format, args);

    va_end(args);
}

//ConsoleHelper::Info(L"Hello Alastor Moody\n");
void ConsoleHelper::Info(const wchar_t* format, ...) {

    va_list args;
    va_start(args, format);

    VPrintColor(ConsoleColor::BrightCyan, format, args);

    va_end(args);
}

ScopedConsoleColor::ScopedConsoleColor(ConsoleColor color) {
    
    m_console = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO info{};

    if (GetConsoleScreenBufferInfo(m_console, &info)) {
        m_oldAttributes = info.wAttributes;
    }

    SetConsoleTextAttribute(m_console, static_cast<WORD>(color));
}

ScopedConsoleColor::~ScopedConsoleColor()
{
    SetConsoleTextAttribute(m_console, m_oldAttributes);
}