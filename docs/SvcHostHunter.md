# SvcHostHunter

> A lightweight Windows threat hunting utility for auditing **ServiceDll** modules hosted by **svchost.exe**.

SvcHostHunter enumerates Windows services running under **svchost.exe**, resolves their associated **ServiceDll**, verifies the Authenticode signature, extracts signer certificate information, and highlights potentially suspicious services that may indicate persistence, tampering, or malicious activity.

The project is intended for **Blue Teams**, **Threat Hunters**, **Incident Responders (DFIR)**, and **Windows Security Engineers**.

---

# Features

* Enumerate all services hosted by **svchost.exe**
* Resolve **ServiceDll** from the registry
* Expand environment variables automatically
* Verify Authenticode signatures
* Support embedded and catalog signatures
* Extract signer certificate information
* Display certificate thumbprint
* Detect unsigned ServiceDll modules
* Detect non-Microsoft signed ServiceDll modules
* Detect ServiceDll located outside Windows directories
* Colorized console output
* Optional output to UTF-8 text file
* Filter output to display only suspicious findings
* Support scanning using a TrustedInstaller security context (when available)

---

# Detection Logic

SvcHostHunter marks a service as suspicious when one or more of the following conditions are met:

* ServiceDll is unsigned
* Signature verification fails
* Signer is not **Microsoft Windows**
* ServiceDll is located outside

```text
C:\Windows\System32\
```

or

```text
C:\Windows\SysWOW64\
```

---

# Command Line

```text
SvcHostHunter.exe [options]
```

## Options

| Option      | Description                                                                                                                                                                                      |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-all`      | Display all services (default).                                                                                                                                                                  |
| `-less`     | Display only suspicious services.                                                                                                                                                                |
| `-ti`       | Run the scan using a TrustedInstaller security context (when supported by the implementation). This is intended to improve access to protected services. Administrative privileges are required. |
| `-o <file>` | Write output to a UTF-8 text file while continuing to display results in the console.                                                                                                            |
| `-h`        | Display help.                                                                                                                                                                                    |

---

# Examples

Scan every service

```cmd
SvcHostHunter.exe
```

Show only suspicious services

```cmd
SvcHostHunter.exe -less
```

Scan everything and save output

```cmd
SvcHostHunter.exe -all -o result.txt
```

Run using TrustedInstaller context

```cmd
SvcHostHunter.exe -ti
```

Run using TrustedInstaller and display only suspicious services

```cmd
SvcHostHunter.exe -ti -less
```

Run using TrustedInstaller and save the results

```cmd
SvcHostHunter.exe -ti -all -o findings.txt
```

---

# Example Output

```text
============================================================

Service : Appinfo
Dll     : C:\Windows\System32\appinfo.dll

Status  : SIGNED
Subject : Microsoft Windows
CertHash: 5C73F4F83E1D8A...

============================================================

Service : ExampleService
Dll     : C:\ProgramData\Example\service.dll

Status  : UNSIGNED / INVALID

[!] ServiceDll outside Windows directory
```

---

# How It Works

SvcHostHunter performs the following steps:

1. Enumerates every Svchost service group
2. Resolves each registered service
3. Reads the **ServiceDll** registry value
4. Expands environment variables
5. Opens the target DLL
6. Searches for a matching catalog signature
7. Verifies the Authenticode signature using **WinVerifyTrust**
8. Extracts signer certificate information
9. Reports suspicious findings

---

# Building

## Requirements

* Windows 10 / Windows 11
* Visual Studio 2019 or later
* Windows SDK
* C++17

## Required Libraries

```text
Wintrust.lib
Crypt32.lib
Advapi32.lib
```

---

# Project Structure

```text
SvcHostHunter/
│
├── SvcHostHunter.cpp
├── SignatureVerifier.cpp
├── SignatureVerifier.h
├── ConsoleHelper.cpp
├── ConsoleHelper.h
├── TrustedInstaller.cpp
├── TrustedInstaller.h
└── README.md
```

---

# Detection Examples

SvcHostHunter is useful for detecting:

* Unsigned service DLLs
* DLL search-order hijacking
* Service persistence
* Malicious service replacement
* Non-Microsoft signed Windows services
* Service DLLs loaded from user-writable locations
* Unexpected third-party service modules
* Potential supply-chain compromises

---

# Use Cases

* Threat Hunting
* Incident Response (IR)
* Digital Forensics (DFIR)
* Malware Investigation
* Windows Security Auditing
* Enterprise Security Assessments
* Baseline Validation
* Service Persistence Detection

---

# Current Limitations

* Only analyzes services using the **ServiceDll** model.
* Does not analyze kernel drivers.
* Does not detect reflective DLL loading.
* Digital signature validation does not determine whether a signed binary is malicious.
* Does not perform reputation or cloud-based malware lookups.

---

# Roadmap

Planned features include:

* JSON output
* CSV output
* SHA-256 hashing
* File version information
* Service start type reporting
* Service account reporting
* VirusTotal integration (optional)
* YARA scanning
* Detection of writable ServiceDll locations
* Symbolic link / junction detection
* Service ACL auditing
* Parallel signature verification
* Performance improvements

---

# Contributing

Contributions are welcome.

If you would like to improve the project, feel free to:

* Submit a pull request
* Report bugs
* Suggest new detection rules
* Improve performance
* Add new hunting capabilities

Please follow the existing coding style and include a clear description of any proposed changes.

---

# License

MIT License

See the LICENSE file for details.

---

# Disclaimer

SvcHostHunter is intended for defensive security, threat hunting, incident response, and Windows security auditing on systems you are authorized to assess.

Always obtain appropriate authorization before scanning production systems or environments that you do not own or manage.
