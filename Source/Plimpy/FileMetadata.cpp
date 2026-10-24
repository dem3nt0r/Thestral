#include "FileMetadata.h"
#include "Handle.h"
#include <aclapi.h>
#include <cwchar>

namespace Plimpy
{
    std::wstring HashFile(const std::wstring& path, ALG_ID algorithm)
    {
        Handle fileHandle(CreateFileW(path.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                      nullptr));
        if (!fileHandle.IsValid())
            return L"";
        HCRYPTPROV provider = 0;
        HCRYPTHASH hash = 0;
        if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return L"";
        if (!CryptCreateHash(provider, algorithm, 0, 0, &hash))
        {
            CryptReleaseContext(provider, 0);
            return L"";
        }
        BYTE readBuffer[65536];
        DWORD bytesRead = 0;
        bool hashSucceeded = true;
        for (;;)
        {
            if (!ReadFile(fileHandle, readBuffer, sizeof readBuffer, &bytesRead, nullptr))
            {
                hashSucceeded = false;
                break;
            }
            if (!bytesRead)
                break;
            if (!CryptHashData(hash, readBuffer, bytesRead, 0))
            {
                hashSucceeded = false;
                break;
            }
        }
        BYTE digest[64]{};
        DWORD digestSizeBytes = sizeof digest;
        std::wstring result;
        if (hashSucceeded && CryptGetHashParam(hash, HP_HASHVAL, digest, &digestSizeBytes, 0))
            for (DWORD i = 0; i < digestSizeBytes; ++i)
            {
                wchar_t hex[3];
                swprintf(hex, 3, L"%02X", digest[i]);
                result += hex;
            }
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return result;
    }

    std::wstring FormatFileTime(const FILETIME& fileTime)
    {
        SYSTEMTIME utcTime{}, localTime{};
        wchar_t timeBuffer[40]{};
        if (FileTimeToSystemTime(&fileTime, &utcTime) &&
            SystemTimeToTzSpecificLocalTime(nullptr, &utcTime, &localTime))
            swprintf(timeBuffer, 40, L"%02u/%02u/%u %02u:%02u", localTime.wDay, localTime.wMonth,
                     localTime.wYear, localTime.wHour, localTime.wMinute);
        return timeBuffer;
    }

    std::wstring GetFileOwner(const std::wstring& path)
    {

        Handle fileHandle(CreateFileW(path.c_str(), READ_CONTROL,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, 0, nullptr));
        if (!fileHandle.IsValid())
            return L"";
        PSID ownerSid = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        std::wstring result;
        if (GetSecurityInfo(fileHandle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &ownerSid,
                            nullptr, nullptr, nullptr, &securityDescriptor) == ERROR_SUCCESS)
        {
            wchar_t accountName[512]{}, domainName[512]{};
            DWORD accountNameLength = 512, domainNameLength = 512;
            SID_NAME_USE sidType{};
            if (LookupAccountSidW(nullptr, ownerSid, accountName, &accountNameLength, domainName,
                                  &domainNameLength, &sidType))
                result = std::wstring(domainName) + L"\\" + accountName;
        }

        if (securityDescriptor)
            LocalFree(securityDescriptor);
        return result;
    }
} // namespace Plimpy
