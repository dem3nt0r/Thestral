#pragma once

#include <string>
#include <Windows.h>

struct SignResult
{
    std::wstring HashFinalCert;
    std::wstring SubjectName;
};

class SignatureVerifier
{
public:
    BOOL VerifySignature(const std::wstring& filePath, SignResult& result);

private:
    static void PrintLastError(const wchar_t* msg);
    static std::wstring ExtractStringFromCertificate(PCCERT_CONTEXT cert, DWORD type, DWORD flags = 0);
    static void GetSignerInfo(HANDLE hWVTStateData, SignResult& result);
};