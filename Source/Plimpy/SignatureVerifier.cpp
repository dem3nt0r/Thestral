#include "SignatureVerifier.h"
#include "Handle.h"
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <vector>

namespace Plimpy
{
    bool IsFileTrusted(const std::wstring& path)
    {
        Handle fileHandle(CreateFileW(path.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                      nullptr));
        // A missing or unreadable file cannot establish signature trust.
        // Keep it visible to both the module and COM scanners.
        if (!fileHandle.IsValid())
            return false;

        HCATADMIN catalogAdmin = nullptr;
        bool catalogFound = false;
        if (CryptCATAdminAcquireContext(&catalogAdmin, nullptr, 0))
        {
            DWORD hashSizeBytes = 0;
            if (CryptCATAdminCalcHashFromFileHandle(fileHandle, &hashSizeBytes, nullptr, 0) &&
                hashSizeBytes)
            {
                std::vector<BYTE> fileHash(hashSizeBytes);
                if (CryptCATAdminCalcHashFromFileHandle(fileHandle, &hashSizeBytes, fileHash.data(),
                                                        0))
                {
                    HCATINFO previousCatalog = nullptr;
                    HCATINFO catalogContext = CryptCATAdminEnumCatalogFromHash(
                        catalogAdmin, fileHash.data(), hashSizeBytes, 0, &previousCatalog);
                    if (catalogContext)
                    {
                        catalogFound = true;
                        CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogContext, 0);
                    }
                }
            }
            CryptCATAdminReleaseContext(catalogAdmin, 0);
        }
        if (catalogFound)
            return true;
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof fileInfo;
        fileInfo.pcwszFilePath = path.c_str();
        fileInfo.hFile = fileHandle;
        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof trustData;
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        GUID verificationAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG verificationStatus = WinVerifyTrust(nullptr, &verificationAction, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &verificationAction, &trustData);
        return verificationStatus == ERROR_SUCCESS;
    }
} // namespace Plimpy
