#include <windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <map>

#include "ConsoleHelper.h"

constexpr size_t F_RID_OFFSET = 0x30;
constexpr size_t F_ACB_OFFSET = 0x38;
constexpr WORD   ACB_DISABLED = 0x0001;

static BOOL EnablePrivilege(const wchar_t* privilegeName)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
    {
        return FALSE;
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return ok && err != ERROR_NOT_ALL_ASSIGNED;
}

static BOOL HexKeyNameToRid(const std::wstring& name, DWORD& outRid)
{
    if (name.empty()) return FALSE;

    for (wchar_t c : name)
    {
        if (!iswxdigit(c)) return FALSE;
    }

    try
    {
        outRid = static_cast<DWORD>(std::stoul(name, NULL, 16));
        return TRUE;
    }
    catch (...)
    {
        return FALSE;
    }
}

static LSTATUS OpenSamKeyBackup(HKEY hParent, const std::wstring& subkey, HKEY* hKey)
{
    return RegOpenKeyExW(
        hParent,
        subkey.c_str(),
        0,
        KEY_READ,
        hKey);
}

static std::map<DWORD, std::wstring> BuildRidToNameMap(HKEY hUsersKey)
{
    std::map<DWORD, std::wstring> ridToName;

    HKEY hNames = NULL;

    wchar_t nameBuf[256];
    memset(&nameBuf, 0, sizeof(nameBuf));
    DWORD index = 0;

    if (OpenSamKeyBackup(hUsersKey, L"Names", &hNames) != ERROR_SUCCESS)
    {
        ConsoleHelper::Print(L"[!] Could not open Users\\Names subkey (access denied?).\n");
        return ridToName;
    }

    while (TRUE)
    {
        DWORD nameLen = static_cast<DWORD>(std::size(nameBuf));
        LSTATUS rc = RegEnumKeyExW(hNames, index, nameBuf, &nameLen, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (rc != ERROR_SUCCESS) { 
            ++index; 
            continue;
        }

        std::wstring username(nameBuf, nameLen);

        HKEY hUserNameKey = NULL;
        if (OpenSamKeyBackup(hNames, username, &hUserNameKey) == ERROR_SUCCESS)
        {
            DWORD type = 0;
            DWORD dataLen = 0;

            LSTATUS qrc = RegQueryValueExW(hUserNameKey, NULL, NULL,
                &type, NULL, &dataLen);
            if (qrc == ERROR_SUCCESS || qrc == ERROR_MORE_DATA)
            {
                ridToName[type] = username;
            }
            RegCloseKey(hUserNameKey);
        }

        ++index;
    }

    RegCloseKey(hNames);

    return ridToName;
}


static BOOL ReadFValue(HKEY hUsersKey, const std::wstring& ridKeyName, std::vector<BYTE>& outData)
{
    HKEY hRidKey = NULL;
    DWORD type = 0;
    DWORD size = 0;
    LSTATUS lResult = 0;

    if (OpenSamKeyBackup(hUsersKey, ridKeyName, &hRidKey) != ERROR_SUCCESS)
        return FALSE;

    
    lResult = RegQueryValueExW(hRidKey, L"F", NULL, &type, NULL, &size);
    if (lResult != ERROR_SUCCESS || type != REG_BINARY || size == 0)
    {
        RegCloseKey(hRidKey);
        return FALSE;
    }

    outData.resize(size);
    lResult = RegQueryValueExW(hRidKey, L"F", NULL, &type, outData.data(), &size);
    RegCloseKey(hRidKey);

    return lResult == ERROR_SUCCESS;
}

static BOOL ExtractFValueFields(const std::vector<BYTE>& fValue, DWORD& outEmbeddedRid, WORD& outAcbFlags)
{
    if (fValue.size() < F_ACB_OFFSET + sizeof(WORD))
        return FALSE;

    memcpy(&outEmbeddedRid, fValue.data() + F_RID_OFFSET, sizeof(DWORD));
    memcpy(&outAcbFlags, fValue.data() + F_ACB_OFFSET, sizeof(WORD));
    return TRUE;
}

static std::wstring WellKnownRidName(DWORD rid)
{
    switch (rid)
    {
    case 500: return L"Administrator";
    case 501: return L"Guest";
    case 502: return L"KRBTGT (DC only)";
    case 512: return L"Domain Admins (DC only)";
    default:  return L"";
    }
}

static std::wstring HexRid(DWORD rid)
{
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::uppercase << rid
        << L" (" << std::dec << rid << L")";
    return ss.str();
}

int wmain()
{

    ConsoleHelper::Print(L"=== RID Hijacking Hunter ===\n");
    ConsoleHelper::Print(L"Checking for mismatches between SAM key-name RID and "
        L"the RID embedded in each account's 'F' value.\n\n");

    BOOL gotBackup = EnablePrivilege(L"SeBackupPrivilege");
    if (!gotBackup)
    {
        ConsoleHelper::Print(L"[!] Could not enable SeBackupPrivilege. "
            L"You likely need to run this elevated (as Administrator), "
            L"and it may still require a SYSTEM context to actually "
            L"read HKLM\\SAM.\n\n");
    }

    HKEY hDomainKey = NULL;
    LSTATUS lStatus = OpenSamKeyBackup(HKEY_LOCAL_MACHINE,
        L"SAM\\SAM\\Domains\\Account\\Users",
        &hDomainKey);
    if (lStatus != ERROR_SUCCESS)
    {
        ConsoleHelper::Print(L"[!] Failed to open HKLM\\SAM\\SAM\\Domain\\Account\\Users "
            L"(error %ld). "
            L"This key is normally readable only by SYSTEM. "
            L"Try running as SYSTEM (e.g. `psexec -s`) or via a "
            L"SYSTEM-context scheduled task / agent.\n", lStatus);
        return 1;
    }

    auto ridToName = BuildRidToNameMap(hDomainKey);
    if (ridToName.empty())
    {
        ConsoleHelper::Print(L"[!] Warning: could not resolve any usernames from "
            L"Users\\Names. Continuing with RID numbers only.\n");
    }

    int totalAccounts = 0;
    int mismatches = 0;

    wchar_t subkeyName[256];
    DWORD index = 0;

    while (TRUE)
    {
        DWORD nameLen = static_cast<DWORD>(std::size(subkeyName));
        LSTATUS erc = RegEnumKeyExW(hDomainKey, index, subkeyName, &nameLen, NULL, NULL, NULL, NULL);
        if (erc == ERROR_NO_MORE_ITEMS) break;
        if (erc != ERROR_SUCCESS) { ++index; continue; }

        std::wstring keyName(subkeyName, nameLen);
        ++index;

        DWORD keyRid = 0;
        if (!HexKeyNameToRid(keyName, keyRid)) {
            continue;
        }

        ++totalAccounts;

        std::vector<BYTE> fValue;
        if (!ReadFValue(hDomainKey, keyName, fValue))
        {
            ConsoleHelper::Print(L"[!] Could not read F value for RID %ws\n", HexRid(keyRid).c_str());
            continue;
        }

        DWORD embeddedRid = 0;
        WORD acbFlags = 0;
        if (!ExtractFValueFields(fValue, embeddedRid, acbFlags))
        {
            ConsoleHelper::Print(L"[!] F value for RID %ws too short to parse (size=%ld)\n", HexRid(keyRid).c_str(), fValue.size());
            continue;
        }

        BOOL disabled = (acbFlags & ACB_DISABLED) != 0;

        std::wstring username = L"<unknown>";
        auto it = ridToName.find(keyRid);
        if (it != ridToName.end()) username = it->second;

        if (embeddedRid != keyRid)
        {
            ++mismatches;
            std::wstring target = WellKnownRidName(embeddedRid);

            ConsoleHelper::Error(L"\n[ALERT] Possible RID Hijacking detected!\n");
            ConsoleHelper::Warning(L"    Account (registry key) : %ws  (key RID %ws)\n    Embedded RID in F value : %ws", 
                username.c_str(), HexRid(keyRid).c_str(), HexRid(embeddedRid).c_str());
            
            if (!target.empty())
                ConsoleHelper::Warning(L"  <-- matches well-known RID for '%ws'", target.c_str());
            
            ConsoleHelper::Warning(L"\n    Account status (0x38)   : %ws\n", (disabled ? L"DISABLED" : L"ENABLED"));
            ConsoleHelper::Error(L"    => This account's on-disk RID does not match "
                L"the RID SAM will actually grant it privileges "
                L"for at logon.\n");
        }
        else
        {
            ConsoleHelper::Print(L"[OK] %-30ws", username.c_str());
            ConsoleHelper::Warning(L"\tRID %-15ws", HexRid(keyRid).c_str());
            ConsoleHelper::Print(L"\tstatus=%ws  (embedded RID matches)\n", (disabled ? L"DISABLED" : L"ENABLED"));
        }
    }

    RegCloseKey(hDomainKey);

    ConsoleHelper::Info(L"\n--- Summary ---\n");
    ConsoleHelper::Info(L"Accounts scanned : %ld\n", totalAccounts);
    ConsoleHelper::Info(L"Mismatches found : %ld\n", mismatches);

    if (mismatches > 0)
    {
        ConsoleHelper::Warning(L"\n[!] One or more accounts show a mismatch between "
            L"their key-name RID and the RID embedded in their "
            L"'F' value. This is the signature of RID Hijacking. "
            L"Investigate the flagged account(s) immediately: "
            L"check who can log on with that account, recent "
            L"logon events (4624) for that SID, and any recent "
            L"SAM registry write/permission changes "
            L"(Sysmon Event ID 12/13/14 on the SAM hive is a "
            L"good hunting source for the write itself).\n");
        return 2;
    }

    ConsoleHelper::Print(L"\nNo RID mismatches found.\n");
    return 0;
}