#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <ntdsapi.h>
#include <sddl.h>
#include <aclapi.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <locale>
#include <utility>
#include <combaseapi.h>
#include <dsgetdc.h>
#include <Lm.h>
#include <winsock.h>

#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Ntdsapi.lib")
#pragma comment(lib, "Advapi32.lib")

static const wchar_t* SD_FLAGS_OID =
L"1.2.840.113556.1.4.801";

struct RightInfo {
    GUID guid;
    const wchar_t* name;
};

static const RightInfo kRights[] = {
    {
        {0x1131f6aa, 0x9c07, 0x11d1,
         {0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}},
        L"DS-Replication-Get-Changes"
    },
    {
        {0x1131f6ad, 0x9c07, 0x11d1,
         {0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}},
        L"DS-Replication-Get-Changes-All"
    },
    {
        {0x89e95b76, 0x444d, 0x4c62,
         {0x99, 0x1a, 0x0f, 0xac, 0xbe, 0xda, 0x64, 0x0c}},
        L"DS-Replication-Get-Changes-In-Filtered-Set"
    }
};

struct Finding {
    std::wstring dn;
    std::wstring account;
    std::wstring sid;
    std::wstring right;
    std::wstring aceType;
    std::wstring accessMask;
    std::wstring inherited;
    std::wstring objectGuid;
};

static std::wstring GuidToString(const GUID& guid)
{
    wchar_t buf[64]{};
    if (!StringFromGUID2(guid, buf, ARRAYSIZE(buf)))
        return L"";
    return buf;
}

static std::wstring RightName(const GUID& guid)
{
    for (const auto& r : kRights) {
        if (IsEqualGUID(guid, r.guid))
            return r.name;
    }
    return L"";
}

static std::wstring SidToString(PSID sid)
{
    if (!sid || !IsValidSid(sid))
        return L"";

    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text))
        return L"";

    std::wstring result(text);
    LocalFree(text);
    return result;
}

static std::wstring SidToAccount(PSID sid)
{
    if (!sid || !IsValidSid(sid))
        return L"<invalid SID>";

    DWORD nameLen = 0, domainLen = 0;
    SID_NAME_USE use{};

    LookupAccountSidW(nullptr, sid, nullptr, &nameLen,
        nullptr, &domainLen, &use);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return SidToString(sid);

    std::vector<wchar_t> name(nameLen);
    std::vector<wchar_t> domain(domainLen);

    if (!LookupAccountSidW(nullptr, sid,
        name.data(), &nameLen,
        domain.data(), &domainLen, &use))
        return SidToString(sid);

    std::wstring result;

    if (domainLen > 0) {
        result = domain.data();
        result += L"\\";
    }

    result += name.data();
    return result;
}

static std::wstring HexMask(ACCESS_MASK mask)
{
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::uppercase << mask;
    return ss.str();
}

static std::wstring CsvEscape(const std::wstring& value)
{
    std::wstring out = L"\"";

    for (wchar_t c : value) {
        if (c == L'"')
            out += L"\"\"";
        else
            out += c;
    }

    out += L"\"";
    return out;
}

static bool DiscoverDomain(
    std::wstring& dcName,
    std::wstring& domainDns)
{
    PDOMAIN_CONTROLLER_INFOW info = nullptr;

    DWORD rc = DsGetDcNameW(
        nullptr, nullptr, nullptr, nullptr,
        DS_DIRECTORY_SERVICE_REQUIRED, &info);

    if (rc != ERROR_SUCCESS) {
        std::wcerr << L"DsGetDcNameW failed: "
            << rc << L"\n";
        return false;
    }

    if (info->DomainControllerName)
        dcName = info->DomainControllerName;

    if (info->DomainName)
        domainDns = info->DomainName;

    NetApiBufferFree(info);
    return !dcName.empty() && !domainDns.empty();
}

static std::wstring DnsToDN(const std::wstring& dns)
{
    std::wstringstream ss;
    size_t start = 0;

    while (start < dns.size()) {
        size_t end = dns.find(L'.', start);
        if (end == std::wstring::npos)
            end = dns.size();

        if (ss.tellp() > 0)
            ss << L",";

        ss << L"DC=" << dns.substr(start, end - start);
        start = end + 1;
    }

    return ss.str();
}

static bool ReadDefaultNamingContext(
    LDAP* ld,
    std::wstring& domainDN)
{
    PWCHAR attrs[] = {
        const_cast<PWCHAR>(L"defaultNamingContext"),
        nullptr
    };

    LDAPMessage* result = nullptr;

    ULONG rc = ldap_search_sW(
        ld,
        const_cast<PWCHAR>(L""),
        LDAP_SCOPE_BASE,
        const_cast<PWCHAR>(L"(objectClass=*)"),
        attrs,
        0,
        &result);

    if (rc != LDAP_SUCCESS) {
        if (result)
            ldap_msgfree(result);
        return false;
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        ldap_msgfree(result);
        return false;
    }

    PWCHAR* values = ldap_get_valuesW(
        ld, entry,
        const_cast<PWCHAR>(L"defaultNamingContext"));

    bool ok = values && values[0];

    if (ok)
        domainDN = values[0];

    if (values)
        ldap_value_freeW(values);

    ldap_msgfree(result);
    return ok;
}

static void InspectSecurityDescriptor(
    const BYTE* bytes,
    ULONG length,
    const std::wstring& dn,
    std::vector<Finding>& findings)
{
    if (!bytes ||
        length < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        return;

    auto sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(
        const_cast<BYTE*>(bytes));

    if (!IsValidSecurityDescriptor(sd))
        return;

    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;

    if (!GetSecurityDescriptorDacl(
        sd, &present, &dacl, &defaulted))
        return;

    if (!present || !dacl)
        return;

    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* rawAce = nullptr;
        if (!GetAce(dacl, i, &rawAce))
            continue;

        auto header = static_cast<ACE_HEADER*>(rawAce);

        bool allow =
            header->AceType == ACCESS_ALLOWED_ACE_TYPE ||
            header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE;

        bool deny =
            header->AceType == ACCESS_DENIED_ACE_TYPE ||
            header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE;

        if (!allow && !deny)
            continue;

        ACCESS_MASK mask = 0;
        PSID sid = nullptr;
        GUID objectGuid{};
        bool hasObjectGuid = false;

        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE ||
            header->AceType == ACCESS_DENIED_ACE_TYPE) {
            auto ace =
                static_cast<ACCESS_ALLOWED_ACE*>(rawAce);

            mask = ace->Mask;
            sid = reinterpret_cast<PSID>(&ace->SidStart);
        }
        else {
            auto ace =
                static_cast<ACCESS_ALLOWED_OBJECT_ACE*>(rawAce);

            mask = ace->Mask;

            BYTE* cursor =
                reinterpret_cast<BYTE*>(&ace->ObjectType);

            if (ace->Flags & ACE_OBJECT_TYPE_PRESENT) {
                CopyMemory(&objectGuid, cursor, sizeof(GUID));
                hasObjectGuid = true;
                cursor += sizeof(GUID);
            }

            if (ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                cursor += sizeof(GUID);

            sid = reinterpret_cast<PSID>(cursor);
        }

        if (!sid || !IsValidSid(sid))
            continue;

        std::wstring right;

        if (hasObjectGuid) {
            right = RightName(objectGuid);
        }

        if (right.empty()) {
            if ((mask & GENERIC_ALL) ||
                (mask & WRITE_DAC) ||
                (mask & WRITE_OWNER)) {
                right = L"Broad permission - review";
            }
            else {
                continue;
            }
        }

        Finding f;
        f.dn = dn;
        f.sid = SidToString(sid);
        f.account = SidToAccount(sid);
        f.right = right;
        f.aceType = allow ? L"ALLOW" : L"DENY";
        f.accessMask = HexMask(mask);
        f.inherited =
            (header->AceFlags & INHERITED_ACE)
            ? L"Yes" : L"No";
        f.objectGuid = hasObjectGuid
            ? GuidToString(objectGuid) : L"";

        findings.push_back(std::move(f));
    }
}

static bool ScanDomain(
    LDAP* ld,
    const std::wstring& domainDN,
    std::vector<Finding>& findings)
{
    char sdFlagsBytes[] = { 0x30, 0x03, 0x02, 0x01, 0x04 };

    berval sdFlagsValue{};
    sdFlagsValue.bv_len = sizeof(sdFlagsBytes);
    sdFlagsValue.bv_val = sdFlagsBytes;

    LDAPControlW sdFlagsControl{};
    sdFlagsControl.ldctl_oid =
        const_cast<PWCHAR>(
            L"1.2.840.113556.1.4.801");
    sdFlagsControl.ldctl_value = sdFlagsValue;
    sdFlagsControl.ldctl_iscritical = TRUE;

    PWCHAR attrs[] = {
        const_cast<PWCHAR>(L"distinguishedName"),
        const_cast<PWCHAR>(L"nTSecurityDescriptor"),
        nullptr
    };

    std::vector<char> cookie;

    do {
        berval cookieValue{};
        cookieValue.bv_len = cookie.size();
        cookieValue.bv_val =
            cookie.empty() ? nullptr : cookie.data();

        LDAPControlW* pageControl = nullptr;

        ULONG rc = ldap_create_page_controlW(
            ld, 500, &cookieValue, TRUE, &pageControl);

        if (rc != LDAP_SUCCESS)
            return false;

        LDAPControlW* controls[] = {
            &sdFlagsControl,
            pageControl,
            nullptr
        };

        LDAPMessage* result = nullptr;
        l_timeval timeout{};
        timeout.tv_sec = 30;

        rc = ldap_search_ext_sW(
            ld,
            const_cast<PWCHAR>(domainDN.c_str()),
            LDAP_SCOPE_SUBTREE,
            const_cast<PWCHAR>(L"(objectClass=*)"),
            attrs,
            0,
            controls,
            nullptr,
            &timeout,
            0,
            &result);

        ldap_control_freeW(pageControl);

        if (rc != LDAP_SUCCESS) {
            std::wcerr << L"LDAP search failed: "
                << rc << L"\n";
            if (result)
                ldap_msgfree(result);
            return false;
        }

        for (LDAPMessage* entry = ldap_first_entry(ld, result);
            entry;
            entry = ldap_next_entry(ld, entry)) {

            PWCHAR dnValue = ldap_get_dnW(ld, entry);
            std::wstring objectDN =
                dnValue ? dnValue : L"";

            if (dnValue)
                ldap_memfreeW(dnValue);

            berval** values = ldap_get_values_lenW(
                ld, entry,
                const_cast<PWCHAR>(
                    L"nTSecurityDescriptor"));

            if (values && values[0]) {
                InspectSecurityDescriptor(
                    reinterpret_cast<const BYTE*>(
                        values[0]->bv_val),
                    static_cast<ULONG>(values[0]->bv_len),
                    objectDN,
                    findings);
            }

            if (values)
                ldap_value_free_len(values);
        }

        LDAPControlW** returnedControls = nullptr;

        rc = ldap_parse_resultW(
            ld, result, nullptr, nullptr, nullptr,
            nullptr, &returnedControls, FALSE);

        if (rc != LDAP_SUCCESS) {
            if (returnedControls)
                ldap_controls_freeW(returnedControls);
            ldap_msgfree(result);
            return false;
        }

        ULONG totalCount = 0;
        berval* nextCookie = nullptr;

        rc = ldap_parse_page_controlW(
            ld, returnedControls, &totalCount, &nextCookie);

        if (returnedControls)
            ldap_controls_freeW(returnedControls);

        ldap_msgfree(result);

        if (rc != LDAP_SUCCESS || !nextCookie) {
            if (nextCookie)
                ber_bvfree(nextCookie);
            return false;
        }

        cookie.clear();

        if (nextCookie->bv_len > 0 &&
            nextCookie->bv_val) {
            cookie.assign(
                nextCookie->bv_val,
                nextCookie->bv_val + nextCookie->bv_len);
        }

        ber_bvfree(nextCookie);

    } while (!cookie.empty());

    return true;
}

static bool WriteCsv(
    const std::wstring& path,
    const std::vector<Finding>& findings)
{
    std::wofstream file(path);
    if (!file)
        return false;

    file.imbue(std::locale(""));

    file << L"DN,Account,SID,Right,ACE,AccessMask,"
        L"Inherited,ObjectGUID\n";

    for (const auto& f : findings) {
        file
            << CsvEscape(f.dn) << L","
            << CsvEscape(f.account) << L","
            << CsvEscape(f.sid) << L","
            << CsvEscape(f.right) << L","
            << CsvEscape(f.aceType) << L","
            << CsvEscape(f.accessMask) << L","
            << CsvEscape(f.inherited) << L","
            << CsvEscape(f.objectGuid) << L"\n";
    }

    return file.good();
}

int wmain(int argc, wchar_t* argv[])
{
    std::wstring dcName, domainDNS, domainDN;

    if (argc >= 2) {
        domainDNS = argv[1];
    }
    else if (!DiscoverDomain(dcName, domainDNS)) {
        std::wcerr << L"Cannot discover current domain.\n";
        return 1;
    }

    LDAP* ld = ldap_initW(
        dcName.empty()
        ? nullptr
        : const_cast<PWCHAR>(dcName.c_str()),
        LDAP_PORT);

    if (!ld) {
        std::wcerr << L"ldap_initW failed.\n";
        return 2;
    }

    ULONG version = LDAP_VERSION3;
    ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG referrals = (ULONG)LDAP_OPT_OFF;
    ldap_set_optionW(ld, LDAP_OPT_REFERRALS, &referrals);

    ULONG rc = ldap_bind_sW(
        ld, nullptr, nullptr, LDAP_AUTH_NEGOTIATE);

    if (rc != LDAP_SUCCESS) {
        std::wcerr << L"LDAP bind failed: " << rc << L"\n";
        ldap_unbind(ld);
        return 3;
    }

    if (!ReadDefaultNamingContext(ld, domainDN)) {
        if (!domainDNS.empty())
            domainDN = DnsToDN(domainDNS);
        else {
            ldap_unbind(ld);
            return 4;
        }
    }

    std::wcout
        << L"Domain DNS: " << domainDNS << L"\n"
        << L"Domain DN: " << domainDN << L"\n";

    std::vector<Finding> findings;
    bool ok = ScanDomain(ld, domainDN, findings);

    ldap_unbind(ld);

    if (!ok)
        std::wcerr << L"Scan incomplete; check LDAP errors.\n";

    if (!WriteCsv(L"DCSyncAclAudit.csv", findings)) {
        std::wcerr << L"Cannot write CSV.\n";
        return 5;
    }

    std::wcout
        << L"Findings: " << findings.size() << L"\n"
        << L"Output: DCSyncAclAudit.csv\n";

    return ok ? 0 : 6;
}
