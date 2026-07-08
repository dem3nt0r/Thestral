#include "RegUtils.h"

BOOL ReadRegistryString(HKEY root, const std::wstring& subkey, const std::wstring& valueName, std::wstring& out)
{
    HKEY hKey = NULL;
    LSTATUS status = 0;

    DWORD type = 0;
    DWORD size = 0;

    status = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }

    status = RegQueryValueExW(
        hKey,
        valueName.empty() ? NULL : valueName.c_str(),
        NULL,
        &type,
        NULL,
        &size);
    if (status != ERROR_SUCCESS || type != REG_SZ) {
        RegCloseKey(hKey);
        return FALSE;
    }

    std::vector<wchar_t> buffer(size / sizeof(wchar_t));

    status = RegQueryValueExW(
        hKey,
        valueName.empty() ? NULL : valueName.c_str(),
        NULL,
        NULL,
        reinterpret_cast<LPBYTE>(buffer.data()),
        &size);

    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        return FALSE;
    }

    out = buffer.data();

    return TRUE;
}

BOOL QueryRegistryLastWriteTime(HKEY root, const std::wstring& subkey, FILETIME& ft) {
    HKEY hKey = NULL;

    LSTATUS status = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &hKey);

    if (status != ERROR_SUCCESS) {
        return FALSE;
    }

    status = RegQueryInfoKeyW(
        hKey,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        &ft);

    RegCloseKey(hKey);

    return status == ERROR_SUCCESS;
}

std::wstring FileTimeToString(const FILETIME& ft)
{
    FILETIME localFt{};
    SYSTEMTIME st{};

    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);

    wchar_t buffer[64]{};
    memset(&buffer, 0, sizeof(buffer));

    swprintf_s(
        buffer,
        L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond);

    return buffer;
}