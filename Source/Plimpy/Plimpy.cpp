#include "ConsoleHelper.h"
#include "ProcessHelper.h"
#include "InjectionScanner.h"
#include "UnsignedScanner.h"
#include "ComScanner.h"
#include "DllUnloader.h"

#include <cerrno>
#include <climits>
#include <cwchar>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <windows.h>

namespace
{
    void PrintUsage()
    {
        Plimpy::ConsoleHelper::Print(
            L"Usage:\n"
            L"  Plimpy.exe [options]\n"
            L"  Plimpy.exe --unload-dll <PID> <DLL Full Path> [--file-output <path>]\n"
            L"\n"
            L"Options:\n"
            L"  -h, --help         Display this help message\n"
            L"  --scan-inject      Scan processes for code injection\n"
            L"  --scan-com         Scan COM registrations\n"
            L"  --show-signature   List DLLs with unverified digital signatures\n"
            L"  --threads <count>  Worker threads, 1-64 (default: 5)\n"
            L"  --file-output <path>  Save UTF-8 output to file and console\n"
            L"  --unload-dll       Unload a DLL from a process\n");
    }

    bool ParsePid(const wchar_t* value, unsigned long& pid)
    {
        if (!value || !*value)
            return false;

        // Accept decimal digits only.
        for (const wchar_t* digit = value; *digit; ++digit)
        {
            if (*digit < L'0' || *digit > L'9')
                return false;
        }

        errno = 0;
        wchar_t* parseEnd = nullptr;
        const unsigned long parsedPid = wcstoul(value, &parseEnd, 10);

        if (errno == ERANGE || parsedPid == 0 || parsedPid > ULONG_MAX || !parseEnd ||
            *parseEnd != L'\0')
        {
            return false;
        }

        pid = parsedPid;
        return true;
    }
    struct ProgramOptions
    {
        bool showHelp = false;
        bool scanInjection = false;
        bool scanCom = false;
        bool scanSignatures = false;
        bool unloadRequested = false;
        unsigned workerCount = Plimpy::DefaultWorkerCount;
        unsigned long pid = 0;
        std::wstring modulePath;
        std::wstring outputPath;
    };

    bool ParseArguments(int argc, wchar_t* argv[], ProgramOptions& options)
    {
        using namespace Plimpy;
        bool threadsSpecified = false;
        options.showHelp = argc == 1;
        for (int argumentIndex = 1; argumentIndex < argc; ++argumentIndex)
        {
            const wchar_t* argument = argv[argumentIndex];
            if (!_wcsicmp(argument, L"-h") || !_wcsicmp(argument, L"--help"))
                options.showHelp = true;
            else if (!_wcsicmp(argument, L"--scan-inject"))
                options.scanInjection = true;
            else if (!_wcsicmp(argument, L"--scan-com"))
                options.scanCom = true;
            else if (!_wcsicmp(argument, L"--show-signature"))
                options.scanSignatures = true;
            else if (!_wcsicmp(argument, L"--threads"))
            {
                unsigned long requestedCount = 0;
                if (argumentIndex + 1 >= argc ||
                    !ParsePid(argv[argumentIndex + 1], requestedCount) ||
                    requestedCount > MaximumWorkerCount)
                {
                    ConsoleHelper::Error(L"Error: --threads requires a count from 1 to 64.\n");
                    return false;
                }
                options.workerCount = static_cast<unsigned>(requestedCount);
                threadsSpecified = true;
                ++argumentIndex;
            }
            else if (!_wcsicmp(argument, L"--file-output"))
            {
                if (!options.outputPath.empty())
                {
                    ConsoleHelper::Error(L"Error: Specify --file-output only once.\n");
                    return false;
                }
                if (argumentIndex + 1 >= argc || !*argv[argumentIndex + 1] ||
                    wcsncmp(argv[argumentIndex + 1], L"--", 2) == 0)
                {
                    ConsoleHelper::Error(L"Error: --file-output requires a file path.\n");
                    return false;
                }
                options.outputPath = argv[++argumentIndex];
            }
            else if (!_wcsicmp(argument, L"--unload-dll"))
            {
                if (options.unloadRequested)
                {
                    ConsoleHelper::Error(L"Error: Specify --unload-dll only once.\n");
                    return false;
                }
                if (argumentIndex + 2 >= argc || !*argv[argumentIndex + 2] ||
                    wcsncmp(argv[argumentIndex + 2], L"--", 2) == 0)
                {
                    ConsoleHelper::Error(L"Error: Expected --unload-dll <PID> <DLL Full Path>\n\n");
                    PrintUsage();
                    return false;
                }
                if (!ParsePid(argv[argumentIndex + 1], options.pid))
                {
                    ConsoleHelper::Error(L"Error: Invalid PID: %ls\n", argv[argumentIndex + 1]);
                    return false;
                }
                options.modulePath = argv[argumentIndex + 2];
                options.unloadRequested = true;
                argumentIndex += 2;
            }
            else
            {
                ConsoleHelper::Error(L"Error: Unknown option: %ls\n\n", argument);
                PrintUsage();
                return false;
            }
        }
        if (options.unloadRequested && (options.scanInjection || options.scanCom ||
                                        options.scanSignatures || threadsSpecified))
        {
            ConsoleHelper::Error(L"Error: --unload-dll cannot be combined with scan options.\n");
            return false;
        }
        return true;
    }

    int ExecuteCommand(const ProgramOptions& options)
    {
        using namespace Plimpy;
        if (options.showHelp)
        {
            PrintUsage();
            return 0;
        }
        EnableDebugPrivilege();
        if (options.unloadRequested)
            return UnloadDll(options.pid, options.modulePath.c_str()) ? 0 : 1;
        if (options.scanInjection)
            ScanInjection(options.workerCount);
        if (options.scanCom)
            ScanComRegistrations(options.workerCount);
        if (options.scanSignatures)
            ScanUnsignedImages(options.workerCount);
        return 0;
    }
} // namespace

int wmain(int argc, wchar_t* argv[])
{
    using namespace Plimpy;
    SetErrorMode(SEM_FAILCRITICALERRORS);
    ProgramOptions options;
    // Validate everything before creating or truncating an output file.
    if (!ParseArguments(argc, argv, options))
        return 1;
    if (!options.outputPath.empty() && !ConsoleHelper::OpenFileOutput(options.outputPath))
    {
        const DWORD error = GetLastError();
        ConsoleHelper::Error(L"Error: Cannot open output file: %ls (error %lu).\n",
                             options.outputPath.c_str(), error);
        return 1;
    }
    int exitCode = 0;
    try
    {
        exitCode = ExecuteCommand(options);
    }
    catch (const std::exception& error)
    {
        ConsoleHelper::Error(L"Error: Command failed: %hs\n", error.what());
        exitCode = 1;
    }
    catch (...)
    {
        ConsoleHelper::Error(L"Error: Command failed.\n");
        exitCode = 1;
    }
    return ConsoleHelper::CloseFileOutput() ? exitCode : 1;
}
