#include "SignatureVerifier.h"

#include <vector>
#include <memory>

#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <VersionHelpers.h>

#include "ConsoleHelper.h"

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

namespace {

    class Wow64RedirectionGuard {

    public:
        explicit Wow64RedirectionGuard(const std::wstring& filePath) {
            BOOL isWow64 = FALSE;
            WCHAR system32[MAX_PATH] = {};

            if (!IsWow64Process(GetCurrentProcess(), &isWow64)) {
                return;
            }

            if (!isWow64) {
                return;
            }

            ExpandEnvironmentStringsW(L"%SystemRoot%\\System32", system32, MAX_PATH);

            if (_wcsnicmp(filePath.c_str(), system32, wcslen(system32)) != 0) {
                return;
            }

            m_disabled = Wow64DisableWow64FsRedirection(&m_oldValue);
        }

        ~Wow64RedirectionGuard() {
            if (m_disabled) {
                Wow64RevertWow64FsRedirection(m_oldValue);
            }
        }

    private:
        PVOID m_oldValue = NULL;
        BOOL  m_disabled = FALSE;
    };
}

void SignatureVerifier::PrintLastError(const wchar_t* msg) {

    LPWSTR buffer = NULL;

    if (FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buffer,
        0,
        NULL))
    {
        ConsoleHelper::PrintColor(ConsoleColor::Red, L"%ls : %ls\n", msg, buffer);
        LocalFree(buffer);
    }
}

std::wstring SignatureVerifier::ExtractStringFromCertificate(PCCERT_CONTEXT cert, DWORD type, DWORD flags)
{
    DWORD size = CertGetNameStringW(cert, type, flags, NULL, NULL, 0);

    if (!size) {
        return L"";
    }

    std::vector<wchar_t> buffer(size);

    CertGetNameStringW(cert, type, flags, NULL, buffer.data(), size);

    return std::wstring(buffer.data());
}

void SignatureVerifier::GetSignerInfo(HANDLE hWVTStateData, SignResult& result)
{
    DWORD hashSize = 0;

    CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(hWVTStateData);

    if (!provData) {
        return;
    }

    CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
    if (!signer) {
        return;
    }

    PCCERT_CONTEXT cert = CertDuplicateCertificateContext(signer->pasCertChain->pCert);

    if (!cert) {
        return;
    }

    CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, NULL, &hashSize);

    if (hashSize) {

        std::vector<BYTE> hash(hashSize);

        if (CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, hash.data(), &hashSize)) {

            wchar_t hashText[128] = {};

            for (DWORD i = 0; i < hashSize; ++i)
            {
                swprintf_s(hashText + (i * 2), 3, L"%02X", hash[i]);
            }

            result.HashFinalCert = hashText;
        }
    }

    result.SubjectName = ExtractStringFromCertificate(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE);

    CertFreeCertificateContext(cert);
}

BOOL SignatureVerifier::VerifySignature(const std::wstring& filePath, SignResult& result) {

    result = {};

    GUID verifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    GUID driverGuid = DRIVER_ACTION_VERIFY;
    HCATADMIN hCatAdmin = NULL;

    DWORD hashSize = 0;
    std::vector<BYTE> fileHash;
    BOOL hashOk = FALSE;

    Wow64RedirectionGuard redirectGuard(filePath);

    HANDLE hFile = CreateFileW(
            filePath.c_str(),
            FILE_READ_ATTRIBUTES |
            FILE_READ_DATA |
            STANDARD_RIGHTS_READ,
            FILE_SHARE_READ |
            FILE_SHARE_WRITE |
            FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintLastError(L"CreateFileW");
        return FALSE;
    }

    if (IsWindows8OrGreater()) {
        CryptCATAdminAcquireContext2(&hCatAdmin, &driverGuid, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    }

    if (!hCatAdmin) {
        if (!CryptCATAdminAcquireContext(&hCatAdmin, &driverGuid, 0)) {
            CloseHandle(hFile);
            return FALSE;
        }
    }

    if (IsWindows8OrGreater()) {
        hashOk = CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashSize, NULL, 0);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            fileHash.resize(hashSize);

            hashOk = CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashSize, fileHash.data(), 0);
        }
    }

    if (!hashOk) {
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0);

        fileHash.resize(hashSize);

        hashOk = CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, fileHash.data(), 0);
    }

    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, fileHash.data(), hashSize, 0, NULL);

    WINTRUST_DATA wd = {};
    WINTRUST_FILE_INFO wfi = {};
    WINTRUST_CATALOG_INFO wci = {};
    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    if (hCatInfo) {
        CATALOG_INFO ci = {};
        ci.cbStruct = sizeof(ci);

        CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0);

        wchar_t memberTag[128] = {};

        for (DWORD i = 0; i < hashSize; ++i) {
            swprintf_s(memberTag + i * 2, 3, L"%02X", fileHash[i]);
        }

        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wd.pCatalog = &wci;

        wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
        wci.pcwszCatalogFilePath = ci.wszCatalogFile;
        wci.pcwszMemberTag = memberTag;
        wci.pcwszMemberFilePath = filePath.c_str();
        wci.hMemberFile = hFile;
        wci.pbCalculatedFileHash = fileHash.data();
        wci.cbCalculatedFileHash = hashSize;
        wci.hCatAdmin = hCatAdmin;
    }
    else {
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.pFile = &wfi;

        wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
        wfi.pcwszFilePath = filePath.c_str();
    }

    LONG verifyResult = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &verifyGuid, &wd);

    BOOL success =
        (verifyResult == ERROR_SUCCESS) ||
        (verifyResult == CERT_E_EXPIRED) ||
        (verifyResult == CERT_E_UNTRUSTEDROOT);
    if (success) {
        GetSignerInfo(wd.hWVTStateData, result);
    }

    if (wd.hWVTStateData) {
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &verifyGuid, &wd);
    }

    if (hCatInfo) {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    }

    if (hCatAdmin) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    }

    CloseHandle(hFile);

    return success;
}