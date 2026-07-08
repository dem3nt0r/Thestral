#include "ConsoleHelper.h"

#include <vector>

FILE* ConsoleHelper::m_LogFile = nullptr;

WORD ConsoleHelper::GetDefaultAttributes()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO info{};

    if (GetConsoleScreenBufferInfo(hConsole, &info))
        return info.wAttributes;

    return 7;
}

BOOL ConsoleHelper::InitializeLogFile(const std::wstring& path)
{
    CloseLogFile();

    return _wfopen_s(
        &m_LogFile,
        path.c_str(),
        L"w, ccs=UTF-8") == 0;
}

void ConsoleHelper::CloseLogFile()
{
    if (m_LogFile)
    {
        fclose(m_LogFile);
        m_LogFile = nullptr;
    }
}

void ConsoleHelper::SetColor(ConsoleColor color)
{
    SetConsoleTextAttribute(
        GetStdHandle(STD_OUTPUT_HANDLE),
        (WORD)color);
}

void ConsoleHelper::ResetColor()
{
    SetConsoleTextAttribute(
        GetStdHandle(STD_OUTPUT_HANDLE),
        GetDefaultAttributes());
}

void ConsoleHelper::Log(
    const wchar_t* format,
    va_list args)
{
    if (!m_LogFile)
        return;

    va_list copy;

    va_copy(copy, args);

    vfwprintf(m_LogFile, format, copy);

    fflush(m_LogFile);

    va_end(copy);
}

void ConsoleHelper::VPrint(
    const wchar_t* format,
    va_list args)
{
    va_list copy;

    va_copy(copy, args);

    vwprintf(format, args);

    Log(format, copy);

    va_end(copy);
}

void ConsoleHelper::Print(
    const wchar_t* format,
    ...)
{
    va_list args;

    va_start(args, format);

    VPrint(format, args);

    va_end(args);
}

void ConsoleHelper::VPrintColor(
    ConsoleColor color,
    const wchar_t* format,
    va_list args)
{
    ScopedConsoleColor scope(color);

    va_list copy;

    va_copy(copy, args);

    vwprintf(format, args);

    Log(format, copy);

    va_end(copy);
}

void ConsoleHelper::PrintColor(
    ConsoleColor color,
    const wchar_t* format,
    ...)
{
    va_list args;

    va_start(args, format);

    VPrintColor(color, format, args);

    va_end(args);
}

void ConsoleHelper::Success(
    const wchar_t* format,
    ...)
{
    va_list args;

    va_start(args, format);

    VPrintColor(
        ConsoleColor::BrightGreen,
        format,
        args);

    va_end(args);
}

void ConsoleHelper::Error(
    const wchar_t* format,
    ...)
{
    va_list args;

    va_start(args, format);

    VPrintColor(
        ConsoleColor::BrightRed,
        format,
        args);

    va_end(args);
}

void ConsoleHelper::Warning(
    const wchar_t* format,
    ...)
{
    va_list args;

    va_start(args, format);

    VPrintColor(
        ConsoleColor::BrightYellow,
        format,
        args);

    va_end(args);
}

void ConsoleHelper::Info(
    const wchar_t* format,
    ...)
{
    va_list args;

    va_start(args, format);

    VPrintColor(
        ConsoleColor::BrightCyan,
        format,
        args);

    va_end(args);
}

ScopedConsoleColor::ScopedConsoleColor(
    ConsoleColor color)
{
    m_console =
        GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO info{};

    if (GetConsoleScreenBufferInfo(
        m_console,
        &info))
    {
        m_oldAttributes =
            info.wAttributes;
    }

    SetConsoleTextAttribute(
        m_console,
        (WORD)color);
}

ScopedConsoleColor::~ScopedConsoleColor()
{
    SetConsoleTextAttribute(
        m_console,
        m_oldAttributes);
}