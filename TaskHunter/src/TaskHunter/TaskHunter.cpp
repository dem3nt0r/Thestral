#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <cstdio>
#include <string>
#include <vector>

#include "SignatureVerifier.h"
#include "ConsoleHelper.h"

#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "advapi32.lib")

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

void AnalyzeCOMClass(const std::wstring& clsid)
{
    std::wstring clsidKey = L"CLSID\\" + clsid;
    std::wstring dllPath{};
    std::wstring appId{};
    SignResult signResult{};
    SignatureVerifier verifier;

    wprintf(L"    CLSID: %ls\n", clsid.c_str());

    ReadRegistryString(HKEY_CLASSES_ROOT, clsidKey + L"\\InprocServer32", L"", dllPath);
    if (!dllPath.empty()) {
        wprintf(L"    DLL: %ls\n", dllPath.c_str());

        if (verifier.VerifySignature(dllPath.c_str(), signResult)) {
            ConsoleHelper::Success(L"    Signature: VALID\n");
            wprintf(L"      Cert Hash: %s\n", signResult.HashFinalCert.c_str());
            wprintf(L"      Publisher: %s\n", signResult.SubjectName.c_str());
        }
        else {
            ConsoleHelper::Error(L"    Signature: INVALID or UNSIGNED\n");
        }
    }

    if (ReadRegistryString(HKEY_CLASSES_ROOT, clsidKey, L"AppID", appId)) {
        
        wprintf(L"    AppID: %ls\n", appId.c_str());

        std::wstring surrogate{};
        std::wstring appIdKey = L"AppID\\" + appId;

        BOOL hasSurrogate = ReadRegistryString(HKEY_CLASSES_ROOT, appIdKey, L"DllSurrogate", surrogate);
        if (hasSurrogate) {
            wprintf(L"    Uses DLLHOST.EXE (DllSurrogate present)\n");

            if (!surrogate.empty()) {
                wprintf(L"    DllSurrogate: %ls\n", surrogate.c_str());
            }
            else {
                wprintf(L"    DllSurrogate: <default dllhost>\n");
            }
        }
        else {
            wprintf(L"    No DllSurrogate\n");
        }
    }
    else {
        wprintf(L"    No AppID\n");
    }

    wprintf(L"\n");
}

void ProcessTask(IRegisteredTask* task)
{
    HRESULT hr;

    LONG count = 0;

    BSTR taskName = NULL;
    BSTR taskPath = NULL;

    ITaskDefinition* taskDef = NULL;
    IActionCollection* actions = NULL;

    task->get_Name(&taskName);
    task->get_Path(&taskPath);

    wprintf(L"==================================================\n");

    wprintf(L"Task Name: %ls\n", taskName);
    wprintf(L"Task Path: %ls\n", taskPath);

    hr = task->get_Definition(&taskDef);
    if (FAILED(hr)) {
        wprintf(L"Failed to get definition\n");
        goto cleanup;
    }

    hr = taskDef->get_Actions(&actions);

    if (FAILED(hr))
    {
        wprintf(L"Failed to get actions\n");

        taskDef->Release();
        goto cleanup;
    }

    actions->get_Count(&count);

    for (LONG i = 1; i <= count; i++)
    {
        IAction* action = NULL;

        hr = actions->get_Item(_variant_t(i), &action);

        if (FAILED(hr))
            continue;

        TASK_ACTION_TYPE type;
        action->get_Type(&type);

        switch (type)
        {
        case TASK_ACTION_EXEC:
        {
            ConsoleHelper::Info(L"[EXEC ACTION]\n");

            IExecAction* iExecAction = NULL;

            hr = action->QueryInterface(IID_IExecAction, (void**)&iExecAction);
            if (SUCCEEDED(hr))
            {
                BSTR path = NULL;
                iExecAction->get_Path(&path);
                wprintf(L"    Executable: %ls\n", (path ? path : L""));
                SysFreeString(path);
                iExecAction->Release();
            }

            break;
        }

        case TASK_ACTION_COM_HANDLER:
        {
            wprintf(L"[COM HANDLER ACTION]\n");

            IComHandlerAction* iComHandlerAction = NULL;

            hr = action->QueryInterface(IID_IComHandlerAction, (void**)&iComHandlerAction);
            if (SUCCEEDED(hr)) {
                BSTR clsid = NULL;
                hr = iComHandlerAction->get_ClassId(&clsid);
                if (SUCCEEDED(hr) && clsid) {
                    AnalyzeCOMClass(clsid);
                    SysFreeString(clsid);
                }
                iComHandlerAction->Release();
            }

            break;
        }

        default:
        {
            wprintf(
                L"[OTHER ACTION TYPE] %d\n",
                type);
            break;
        }
        }

        action->Release();
    }

    actions->Release();
    taskDef->Release();

cleanup:

    SysFreeString(taskName);
    SysFreeString(taskPath);
}

void EnumerateFolder(ITaskFolder* folder)
{
    HRESULT hr;

    IRegisteredTaskCollection* iRegisteredTaskCollection = NULL;
    ITaskFolderCollection* iTaskFolderCollection = NULL;

    hr = folder->GetTasks(
        TASK_ENUM_HIDDEN,
        &iRegisteredTaskCollection);

    if (SUCCEEDED(hr))
    {
        LONG count = 0;
        iRegisteredTaskCollection->get_Count(&count);

        for (LONG i = 1; i <= count; i++)
        {
            IRegisteredTask* iRegisteredTask = NULL;
            hr = iRegisteredTaskCollection->get_Item(_variant_t(i), &iRegisteredTask);
            if (SUCCEEDED(hr)) {
                ProcessTask(iRegisteredTask);
                iRegisteredTask->Release();
            }
        }

        iRegisteredTaskCollection->Release();
    }

    // Enumerate subfolders
    hr = folder->GetFolders(0, &iTaskFolderCollection);
    if (SUCCEEDED(hr))
    {
        LONG count = 0;
        iTaskFolderCollection->get_Count(&count);

        for (LONG i = 1; i <= count; i++)
        {
            ITaskFolder* subFolder = NULL;
            hr = iTaskFolderCollection->get_Item(_variant_t(i), &subFolder);
            if (SUCCEEDED(hr))
            {
                EnumerateFolder(subFolder);
                subFolder->Release();
            }
        }

        iTaskFolderCollection->Release();
    }
}

int wmain(int argc, wchar_t* argv[])
{
    HRESULT hr = S_FALSE;
    ITaskService* iTaskService = NULL;
    ITaskFolder* iTaskFolder = NULL;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    if (FAILED(hr)) {
        wprintf(L"CoInitializeEx failed: 0x%08X\n", hr);
        return 1;
    }

    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL);
    if (FAILED(hr)) {
        wprintf(L"CoInitializeSecurity failed: 0x%08X\n", hr);
        CoUninitialize();
        return 1;
    }

    hr = CoCreateInstance(
        CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&iTaskService);
    if (FAILED(hr)) {
        wprintf(L"CoCreateInstance failed: 0x%08X\n", hr);
        CoUninitialize();
        return 1;
    }

    hr = iTaskService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        wprintf(L"Connect failed: 0x%08X\n", hr);
        iTaskService->Release();
        CoUninitialize();
        return 1;
    }

    hr = iTaskService->GetFolder(_bstr_t(L"\\"), &iTaskFolder);
    if (FAILED(hr)) {
        wprintf(L"GetFolder failed: 0x%08X\n", hr);
        iTaskService->Release();
        CoUninitialize();
        return 1;
    }

    EnumerateFolder(iTaskFolder);

    iTaskFolder->Release();
    iTaskService->Release();

    CoUninitialize();

    return 0;
}