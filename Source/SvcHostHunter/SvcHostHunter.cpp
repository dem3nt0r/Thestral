#include <Windows.h>
#include <string>
#include <set>
#include <fstream>

#include "SignatureVerifier.h"
#include "ConsoleHelper.h"
#include "RunAsTI.h"

enum class OutputMode
{
    Full,
    SuspiciousOnly
};

struct ProgramOptions
{
    OutputMode Mode = OutputMode::Full;

    BOOL RunAsTrustedInstaller = FALSE;

    std::wstring OutputFile;
};

BOOL GetServiceDll(
    const std::wstring& serviceName,
    std::wstring& dllPath)
{
    HKEY hKey = NULL;

    WCHAR buffer[MAX_PATH] = {};
    WCHAR expanded[MAX_PATH] = {};

    DWORD size = sizeof(buffer);
    DWORD type = 0;

    std::wstring regPath =
        L"SYSTEM\\CurrentControlSet\\Services\\" +
        serviceName +
        L"\\Parameters";

    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        regPath.c_str(),
        0,
        KEY_READ,
        &hKey);

    if (status != ERROR_SUCCESS)
        return FALSE;

    status = RegQueryValueExW(
        hKey,
        L"ServiceDll",
        NULL,
        &type,
        (LPBYTE)buffer,
        &size);

    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
        return FALSE;

    if (type != REG_SZ &&
        type != REG_EXPAND_SZ)
        return FALSE;

    ExpandEnvironmentStringsW(
        buffer,
        expanded,
        ARRAYSIZE(expanded));

    dllPath = expanded;

    return TRUE;
}

BOOL IsWindowsDll(const std::wstring& dll)
{
    if (_wcsnicmp(dll.c_str(),
        L"C:\\Windows\\System32\\", 20) == 0)
        return TRUE;

    if (_wcsnicmp(dll.c_str(),
        L"C:\\Windows\\SysWOW64\\", 20) == 0)
        return TRUE;

    return FALSE;
}

BOOL IsSuspicious(
    const std::wstring& dll,
    BOOL signedStatus,
    const SignResult& sign)
{
    if (!signedStatus)
        return TRUE;

    if (_wcsicmp(
        sign.SubjectName.c_str(),
        L"Microsoft Windows") != 0)
        return TRUE;

    if (!IsWindowsDll(dll))
        return TRUE;

    return FALSE;
}

void PrintResult(
    const std::wstring& service,
    const std::wstring& dll,
    BOOL signedStatus,
    const SignResult& sign)
{
    ConsoleHelper::Info(
        L"\n============================================================\n");

    ConsoleHelper::Print(
        L"Service : %ls\n",
        service.c_str());

    ConsoleHelper::Print(
        L"Dll     : %ls\n",
        dll.c_str());

    if (signedStatus)
    {
        ConsoleHelper::Success(
            L"Status  : SIGNED\n");

        ConsoleHelper::Print(
            L"Subject : %ls\n",
            sign.SubjectName.c_str());

        ConsoleHelper::Print(
            L"CertHash: %ls\n",
            sign.HashFinalCert.c_str());

        if (_wcsicmp(
            sign.SubjectName.c_str(),
            L"Microsoft Windows") != 0)
        {
            ConsoleHelper::Warning(
                L"[!] Non-Microsoft signer detected\n");
        }
    }
    else
    {
        ConsoleHelper::Error(
            L"Status  : UNSIGNED / INVALID\n");
    }

    if (!IsWindowsDll(dll))
    {
        ConsoleHelper::Warning(
            L"[!] ServiceDll outside Windows directory\n");
    }
}

void AuditSvchostDlls(const ProgramOptions& options)
{
    HKEY hKey = NULL;
    LONG status = 0;
    DWORD index = 0;
    WCHAR valueName[256] = { 0 };
    BYTE data[16384] = { 0 };
    DWORD valueNameLength = 0;
    DWORD dataLength = 0;
    DWORD type = 0;

    SignatureVerifier verifier;

    std::set<std::wstring> processed;

    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
        0,
        KEY_READ,
        &hKey);

    if (status != ERROR_SUCCESS)
    {
        ConsoleHelper::Error(
            L"Unable to open Svchost registry.\n");
        return;
    }

    while (TRUE)
    {
        valueNameLength = ARRAYSIZE(valueName);

        dataLength = sizeof(data);

        ZeroMemory(valueName,
            sizeof(valueName));

        ZeroMemory(data,
            sizeof(data));

        status = RegEnumValueW(
            hKey,
            index++,
            valueName,
            &valueNameLength,
            NULL,
            &type,
            data,
            &dataLength);

        if (status == ERROR_NO_MORE_ITEMS)
            break;

        if (status != ERROR_SUCCESS)
            continue;

        if (type != REG_MULTI_SZ)
            continue;

        WCHAR* serviceName =
            (WCHAR*)data;

        while (*serviceName)
        {
            std::wstring service(serviceName);

            serviceName +=
                wcslen(serviceName) + 1;

            if (!processed.insert(service).second)
                continue;

            std::wstring dll;

            if (!GetServiceDll(service, dll))
                continue;

            SignResult sign = {};

            BOOL signedStatus =
                verifier.VerifySignature(
                    dll,
                    sign);

            BOOL suspicious =
                IsSuspicious(
                    dll,
                    signedStatus,
                    sign);

            if (options.Mode ==
                OutputMode::SuspiciousOnly &&
                !suspicious)
            {
                continue;
            }

            PrintResult(
                service,
                dll,
                signedStatus,
                sign);
        }
    }

    RegCloseKey(hKey);
}

void PrintHelp()
{
    wprintf(L"\n");
    wprintf(L"SvcHostHunter\n\n");
    wprintf(L"Options:\n");
    wprintf(L"  -all               Output all services\n");
    wprintf(L"  -less              Output suspicious services only\n");
    wprintf(L"  -ti                Impersonate TrustedInstaller\n");
    wprintf(L"  -o <file>          Output to file\n");
    wprintf(L"  -h                 Show help\n");
}

BOOL ParseArguments(
    int argc,
    wchar_t* argv[],
    ProgramOptions& options)
{
    for (int i = 1; i < argc; i++)
    {
        if (!_wcsicmp(argv[i], L"-all"))
        {
            options.Mode =
                OutputMode::Full;
        }
        else if (!_wcsicmp(argv[i], L"-less"))
        {
            options.Mode =
                OutputMode::SuspiciousOnly;
        }
        else if (!_wcsicmp(argv[i], L"-ti"))
        {
            options.RunAsTrustedInstaller =
                TRUE;
        }
        else if (!_wcsicmp(argv[i], L"-o"))
        {
            if (i + 1 >= argc)
                return FALSE;

            options.OutputFile =
                argv[++i];
        }
        else if (!_wcsicmp(argv[i], L"-h"))
        {
            PrintHelp();
            exit(0);
        }
        else
        {
            return FALSE;
        }
    }

    return TRUE;
}

void RemoveITSuffix(std::wstring& str)
{
    constexpr wchar_t suffix[] = L"-ti";
    constexpr size_t suffixLen = sizeof(suffix) / sizeof(wchar_t) - 1;

    if (str.length() >= suffixLen &&
        str.compare(str.length() - suffixLen, suffixLen, suffix) == 0)
    {
        str.erase(str.length() - suffixLen);
    }
}

int wmain(
    int argc,
    wchar_t* argv[])
{
    ProgramOptions options;

    if (!ParseArguments(
        argc,
        argv,
        options))
    {
        PrintHelp();
        return 1;
    }

    if (!options.OutputFile.empty())
    {
        FILE* fp = nullptr;

        _wfreopen_s(
            &fp,
            options.OutputFile.c_str(),
            L"w, ccs=UTF-8",
            stdout);
    }

    if (options.RunAsTrustedInstaller)
    {
        std::wstring cmd(GetCommandLineW());
        RemoveITSuffix(cmd);
        if (!CreateProcessAsTrustedInstaller((LPWSTR)cmd.c_str()))
        {
            ConsoleHelper::Error(L"Failed to impersonate TrustedInstaller.\n");
            return 1;
        }

        ConsoleHelper::Success(L"[+] Running as TrustedInstaller\n");
        return 0;
    }

    AuditSvchostDlls(options);

    getc(stdin);

    return 0;
}