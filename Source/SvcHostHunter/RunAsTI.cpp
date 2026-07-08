#include "RunAsTI.h"
#include "ConsoleHelper.h"

#include <string>
#include <userenv.h>
#include <Shlobj.h>
#include <shlwapi.h>
#include <TlHelp32.h>

#pragma comment(lib,"Userenv.lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Shell32.lib")

static BOOL EnablePrivilege(const std::wstring privilegeName)
{
	HANDLE hToken = nullptr;
	BOOL res = FALSE;

	do {
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			wprintf(L"OpenProcessToken %ld\n", GetLastError());
			break;
		}

		LUID luid;
		if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
			//FNERROR(L"LookupPrivilegeValueW('" + privilegeName + L"')");
			wprintf(L"LookupPrivilegeValueW %ld\n", GetLastError());
			break;
		}

		TOKEN_PRIVILEGES tp = { 0 };
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!(res = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))) {
			wprintf(L"AdjustTokenPrivileges('%ws')\n", privilegeName.data());
			break;
		}

	} while (FALSE);

	if (hToken == nullptr)
		CloseHandle(hToken);

	return res;
}

static BOOL ImpersonateToProcess(const std::wstring processName)
{
	HANDLE hSnapshot = nullptr;
	HANDLE hSystemProcess = nullptr, hSystemToken = nullptr, hDupToken = nullptr;
	BOOL res = FALSE;

	do {

		if ((hSnapshot = CreateToolhelp32Snapshot(
			TH32CS_SNAPPROCESS,
			0)) == INVALID_HANDLE_VALUE) {
			ConsoleHelper::Error(L"CreateToolhelp32Snapshot %ld\n", GetLastError());
			break;
		}

		PROCESSENTRY32W pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hSnapshot, &pe))
			while (Process32NextW(hSnapshot, &pe) && _wcsicmp(pe.szExeFile, processName.c_str()));
		else {
			ConsoleHelper::Error(L"Process32FirstW %ws %ld\n", processName.c_str(), GetLastError());
			break;
		}

		if (_wcsicmp(pe.szExeFile, processName.c_str())) {
			ConsoleHelper::Error(L"Cant't found process %ws\n", processName.c_str());
			break;
		}

		if ((hSystemProcess = OpenProcess(
			PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
			FALSE,
			pe.th32ProcessID)) == nullptr) {
			ConsoleHelper::Error(L"OpenProcess %ws %ld\n", processName.c_str(), GetLastError());
			break;
		}

		if (!OpenProcessToken(
			hSystemProcess,
			MAXIMUM_ALLOWED,
			&hSystemToken)) {
			ConsoleHelper::Error(L"OpenProcessToken %ws %ld\n", processName.c_str(), GetLastError());
			break;
		}

		SECURITY_ATTRIBUTES tokenAttributes;
		tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		tokenAttributes.lpSecurityDescriptor = nullptr;
		tokenAttributes.bInheritHandle = FALSE;
		if (!DuplicateTokenEx(
			hSystemToken,
			MAXIMUM_ALLOWED,
			&tokenAttributes,
			SecurityImpersonation,
			TokenImpersonation,
			&hDupToken)) {
			ConsoleHelper::Error(L"DuplicateTokenEx %ws %ld\n", processName.c_str(), GetLastError());
			break;
		}

		if (!(res = ImpersonateLoggedOnUser(hDupToken))) {
			ConsoleHelper::Error(L"ImpersonateLoggedOnUser %ws %ld\n", processName.c_str(), GetLastError());
			break;
		}

	} while (FALSE);

	if (hSystemProcess != nullptr)
		CloseHandle(hSystemProcess);

	if (hDupToken != nullptr)
		CloseHandle(hDupToken);

	if (hSnapshot != nullptr)
		CloseHandle(hSnapshot);

	return (BOOL)res;
}

static DWORD GetPidTrustedInstallerService()
{
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;
	DWORD dwProcessId = 0;
	BOOL res = TRUE, started = TRUE;

	do {

		if ((hSCManager = OpenSCManagerW(
			nullptr,
			SERVICES_ACTIVE_DATABASE,
			GENERIC_EXECUTE)) == nullptr) {
			ConsoleHelper::Error(L"OpenSCManagerW %ld\n", GetLastError());
			break;
		}

		if ((hService = OpenServiceW(
			hSCManager,
			L"TrustedInstaller",
			GENERIC_READ | GENERIC_EXECUTE)) == nullptr) {
			ConsoleHelper::Error(L"OpenServiceW('TrustedInstaller') %ld\n", GetLastError());
			break;
		}

		SERVICE_STATUS_PROCESS statusBuffer = { 0 };
		DWORD bytesNeeded;
		while (dwProcessId == 0 &&
			started &&
			(res = QueryServiceStatusEx(
				hService,
				SC_STATUS_PROCESS_INFO,
				reinterpret_cast<LPBYTE>(&statusBuffer),
				sizeof(SERVICE_STATUS_PROCESS),
				&bytesNeeded))) {

			switch (statusBuffer.dwCurrentState) {
			case SERVICE_STOPPED:
				started = StartServiceW(hService, 0, nullptr);
				if (!started) {
					ConsoleHelper::Error(L"StartServiceW('TrustedInstaller') %ld\n", GetLastError());
				}
				break;
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				Sleep(statusBuffer.dwWaitHint);
				break;
			case SERVICE_RUNNING:
				dwProcessId = statusBuffer.dwProcessId;
				break;
			}
		}

		if (!res) {
			ConsoleHelper::Error(L"QueryServiceStatusEx('TrustedInstaller') %ld\n", GetLastError());
		}

	} while (FALSE);

	if (hService != nullptr)
		CloseServiceHandle(hService);

	if (hSCManager != nullptr)
		CloseServiceHandle(hSCManager);

	return dwProcessId;
}

BOOL CreateProcessAsTrustedInstaller(LPWSTR cmd)
{
	if (!EnablePrivilege(SE_DEBUG_NAME) ||
		!EnablePrivilege(SE_IMPERSONATE_NAME) ||
		!ImpersonateToProcess(L"winlogon.exe"))
		return FALSE;

	HANDLE hTIProcess = nullptr, hTIToken = nullptr, hDupToken = nullptr;
	HANDLE hToken = nullptr;
	LPVOID lpEnvironment = nullptr;
	LPWSTR lpBuffer = nullptr;
	BOOL res = FALSE;

	do {

		DWORD pid = GetPidTrustedInstallerService();
		if (!pid)
			break;

		if ((hTIProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid)) == nullptr) {
			ConsoleHelper::Error(L"OpenProcess('TrustedInstaller') %ld\n", GetLastError());
			break;
		}

		if (!OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken)) {
			ConsoleHelper::Error(L"OpenProcessToken('TrustedInstaller') %ld\n", GetLastError());
			break;
		}

		SECURITY_ATTRIBUTES tokenAttributes;
		tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		tokenAttributes.lpSecurityDescriptor = nullptr;
		tokenAttributes.bInheritHandle = FALSE;
		if (!DuplicateTokenEx(
			hTIToken,
			MAXIMUM_ALLOWED,
			&tokenAttributes,
			SecurityImpersonation,
			TokenImpersonation,
			&hDupToken)) {
			ConsoleHelper::Error(L"DuplicateTokenEx %ld\n", GetLastError());
			break;
		}

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken)) {
			ConsoleHelper::Error(L"OpenProcessToken(GetCurrentProcess()) %ld\n", GetLastError());
			break;
		}

		if (!CreateEnvironmentBlock(
			&lpEnvironment,
			hToken,
			TRUE)) {
			ConsoleHelper::Error(L"CreateEnvironmentBlock %ld\n", GetLastError());
			break;
		}

		DWORD nBufferLength = GetCurrentDirectoryW(0, nullptr);
		if (!nBufferLength)
			break;

		lpBuffer = (LPWSTR)(new wchar_t[nBufferLength] {0});
		if (!GetCurrentDirectoryW(nBufferLength, lpBuffer)) {
			ConsoleHelper::Error(L"GetCurrentDirectoryW %ld\n", GetLastError());
			break;
		}

		STARTUPINFOW startupInfo;
		ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
		startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
		PROCESS_INFORMATION processInfo;
		ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
		res = CreateProcessWithTokenW(
			hDupToken,
			LOGON_WITH_PROFILE,
			nullptr,
			cmd,
			CREATE_UNICODE_ENVIRONMENT,
			lpEnvironment,
			lpBuffer,
			&startupInfo,
			&processInfo);
		if (!res) {
			ConsoleHelper::Error(L"CreateProcessWithTokenW(%ws) %ld\n", cmd, GetLastError());
		}

	} while (FALSE);

	if (lpBuffer == nullptr)
		delete lpBuffer;

	if (lpEnvironment == nullptr)
		DestroyEnvironmentBlock(lpEnvironment);

	if (hToken == nullptr)
		CloseHandle(hToken);

	if (hDupToken == nullptr)
		CloseHandle(hDupToken);

	if (hTIToken == nullptr)
		CloseHandle(hTIToken);

	if (hTIProcess == nullptr)
		CloseHandle(hTIProcess);

	return (BOOL)res;
}