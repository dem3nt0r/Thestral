#include "ConsoleHelper.h"
#include "WindowsPlatform.h"

#include <cstdarg>
#include <cstdio>
#include <algorithm>

namespace Plimpy
{
    namespace
    {
        std::mutex outputMutex;
        HANDLE outputFile = INVALID_HANDLE_VALUE;
        bool outputFailed = false;

        bool WriteBytes(HANDLE destination, const char* bytes, size_t byteCount)
        {
            size_t offset = 0;
            while (offset < byteCount)
            {
                const DWORD chunkSize =
                    static_cast<DWORD>(std::min(byteCount - offset, static_cast<size_t>(MAXDWORD)));
                DWORD bytesWritten = 0;
                if (!WriteFile(destination, bytes + offset, chunkSize, &bytesWritten, nullptr))
                    return false;
                if (!bytesWritten)
                {
                    SetLastError(ERROR_WRITE_FAULT);
                    return false;
                }
                offset += bytesWritten;
            }
            return true;
        }

        void ReportFileFailure(DWORD error)
        {
            if (outputFailed)
                return;
            outputFailed = true;
            // Do not route a failed file write back through the file sink.
            fwprintf(stderr, L"Error: File output failed: %lu. Console output continues.\n", error);
        }

        void WriteMessage(DWORD stream, const wchar_t* format, va_list arguments)
        {
            try
            {
                va_list countArguments;
                va_copy(countArguments, arguments);
                const int characterCount = _vscwprintf(format, countArguments);
                va_end(countArguments);
                if (characterCount < 0)
                {
                    ReportFileFailure(ERROR_INVALID_DATA);
                    return;
                }
                if (!characterCount)
                    return;
                std::vector<wchar_t> text(static_cast<size_t>(characterCount) + 1);
                va_list textArguments;
                va_copy(textArguments, arguments);
                const int formattedCount =
                    vswprintf(text.data(), text.size(), format, textArguments);
                va_end(textArguments);
                if (formattedCount < 0)
                {
                    ReportFileFailure(ERROR_INVALID_DATA);
                    return;
                }

                HANDLE console = GetStdHandle(stream);
                DWORD consoleMode = 0;
                const bool isConsole = GetConsoleMode(console, &consoleMode) != FALSE;
                if (isConsole)
                {
                    size_t offset = 0;
                    while (offset < static_cast<size_t>(formattedCount))
                    {
                        DWORD charactersWritten = 0;
                        if (!WriteConsoleW(console, text.data() + offset,
                                           static_cast<DWORD>(formattedCount - offset),
                                           &charactersWritten, nullptr) ||
                            !charactersWritten)
                            break;
                        offset += charactersWritten;
                    }
                }

                const int byteCount =
                    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), formattedCount,
                                        nullptr, 0, nullptr, nullptr);
                if (!byteCount)
                {
                    ReportFileFailure(GetLastError());
                    return;
                }
                std::vector<char> bytes(static_cast<size_t>(byteCount));
                if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), formattedCount,
                                         bytes.data(), byteCount, nullptr, nullptr))
                {
                    ReportFileFailure(GetLastError());
                    return;
                }
                if (!isConsole)
                    WriteBytes(console, bytes.data(), bytes.size());
                if (outputFile != INVALID_HANDLE_VALUE && !outputFailed &&
                    !WriteBytes(outputFile, bytes.data(), bytes.size()))
                    ReportFileFailure(GetLastError());
            }
            catch (...)
            {
                ReportFileFailure(ERROR_NOT_ENOUGH_MEMORY);
            }
        }

        std::wstring SanitizeCell(const std::wstring& value)
        {
            if (value.empty())
                return L"-";
            std::wstring result;
            for (const wchar_t character : value)
            {
                switch (character)
                {
                case L'\n':
                    result += L"\\n";
                    break;
                case L'\r':
                    result += L"\\r";
                    break;
                case L'\t':
                    result += L"\\t";
                    break;
                default:
                    if (character < L' ' || (character >= 0x7F && character <= 0x9F) ||
                        character == L'|')
                    {
                        wchar_t escaped[8]{};
                        swprintf(escaped, 8, L"\\x%02X", static_cast<unsigned>(character));
                        result += escaped;
                    }
                    else
                        result += character;
                }
            }
            return result;
        }
    } // namespace

    ConsoleTable::ConsoleTable(const wchar_t* title,
                               std::initializer_list<TableColumn> tableColumns)
        : columns(tableColumns), title(title)
    {
        for (TableColumn& column : columns)
        {
            column.title = SanitizeCell(column.title);
            column.width = std::max(column.width, column.title.size());
        }
    }

    ConsoleTable::~ConsoleTable()
    {
        // Scanners join their workers before the table leaves scope.
        std::sort(rows.begin(), rows.end());
        ConsoleHelper::Print(L"\n%ls\n", title.c_str());
        std::vector<std::wstring> headings;
        for (const TableColumn& column : columns)
            headings.push_back(column.title);
        PrintCells(headings);
        PrintSeparator();
        for (const std::vector<std::wstring>& row : rows)
            PrintCells(row);
        if (rows.empty())
            ConsoleHelper::Print(L"No findings reported.\n");
        ConsoleHelper::Print(L"\n");
    }

    void ConsoleTable::PrintSeparator() const
    {
        std::wstring line;
        for (size_t columnIndex = 0; columnIndex < columns.size(); ++columnIndex)
        {
            if (columnIndex)
                line += L"  ";
            line += std::wstring(columns[columnIndex].width, L'-');
        }
        ConsoleHelper::Print(L"%ls\n", line.c_str());
    }

    void ConsoleTable::PrintCells(const std::vector<std::wstring>& cells) const
    {
        std::wstring line;
        for (size_t columnIndex = 0; columnIndex < columns.size(); ++columnIndex)
        {
            line += cells[columnIndex];
            if (columnIndex + 1 < columns.size())
                line +=
                    std::wstring(columns[columnIndex].width - cells[columnIndex].size() + 2, L' ');
        }
        ConsoleHelper::Print(L"%ls\n", line.c_str());
    }

    void ConsoleTable::PrintRow(std::initializer_list<std::wstring> rowCells)
    {
        if (rowCells.size() != columns.size())
        {
            ConsoleHelper::Error(L"[!] Table column count mismatch.\n");
            return;
        }
        std::vector<std::wstring> cells;
        for (const std::wstring& cell : rowCells)
            cells.push_back(SanitizeCell(cell));
        std::lock_guard<std::mutex> lock(rowsMutex);
        for (size_t columnIndex = 0; columnIndex < columns.size(); ++columnIndex)
            columns[columnIndex].width =
                std::max(columns[columnIndex].width, cells[columnIndex].size());
        rows.push_back(cells);
    }

    bool ConsoleHelper::OpenFileOutput(const std::wstring& path)
    {
        std::lock_guard<std::mutex> lock(outputMutex);
        if (path.empty() || outputFile != INVALID_HANDLE_VALUE)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }
        outputFile = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (outputFile == INVALID_HANDLE_VALUE)
            return false;
        outputFailed = false;
        return true;
    }

    bool ConsoleHelper::CloseFileOutput()
    {
        std::lock_guard<std::mutex> lock(outputMutex);
        if (outputFile != INVALID_HANDLE_VALUE)
        {
            if (!FlushFileBuffers(outputFile))
                ReportFileFailure(GetLastError());
            if (!CloseHandle(outputFile))
                ReportFileFailure(GetLastError());
            outputFile = INVALID_HANDLE_VALUE;
        }
        return !outputFailed;
    }

    void ConsoleHelper::Print(const wchar_t* format, ...)
    {
        std::lock_guard<std::mutex> lock(outputMutex);
        va_list arguments;
        va_start(arguments, format);
        WriteMessage(STD_OUTPUT_HANDLE, format, arguments);
        va_end(arguments);
    }

    void ConsoleHelper::Error(const wchar_t* format, ...)
    {
        std::lock_guard<std::mutex> lock(outputMutex);
        va_list arguments;
        va_start(arguments, format);
        WriteMessage(STD_ERROR_HANDLE, format, arguments);
        va_end(arguments);
    }
} // namespace Plimpy
