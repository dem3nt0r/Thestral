#pragma once

#include <initializer_list>
#include <string>
#include <vector>
#include <mutex>

namespace Plimpy
{
    class ConsoleHelper
    {
      public:
        static bool OpenFileOutput(const std::wstring& path);
        static bool CloseFileOutput();
        static void Print(const wchar_t* format, ...);
        static void Error(const wchar_t* format, ...);
    };

    struct TableColumn
    {
        std::wstring title;
        size_t width;
    };

    class ConsoleTable
    {
      public:
        ConsoleTable(const wchar_t* title, std::initializer_list<TableColumn> columns);
        ~ConsoleTable();

        void PrintRow(std::initializer_list<std::wstring> cells);

        ConsoleTable(const ConsoleTable&) = delete;
        ConsoleTable& operator=(const ConsoleTable&) = delete;

      private:
        void PrintSeparator() const;
        void PrintCells(const std::vector<std::wstring>& cells) const;

        std::vector<TableColumn> columns;
        std::wstring title;
        std::vector<std::vector<std::wstring>> rows;
        std::mutex rowsMutex;
    };
} // namespace Plimpy
