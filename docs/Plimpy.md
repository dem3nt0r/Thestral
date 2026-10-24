# Plimpy

Plimpy is a Windows x86/x64 threat hunting tool for inspecting processes, loaded executable images, and per-user COM server registrations. It reports observations that can help analysts investigate code injection, image modification, and unverified files.

The tool is intended for threat hunting, incident response, and Windows security auditing. Findings require investigation; legitimate software can trigger the same checks.

---

## Features

- Inspects supported processes for thread start addresses outside enumerated modules.
- Checks selected thread stacks for addresses outside enumerated modules.
- Compares on-disk and in-memory PE timestamps and entry-point bytes.
- Enumerates loaded users' x86 and x64 per-user `InprocServer32` COM registrations.
- Reports executable images whose signature trust could not be established.
- Reports file creation time, owner, PE timestamp, MD5, SHA-1, and SHA-256.
- Provides a standalone command to request DLL unloading from a process.
- Runs scan jobs in parallel with five workers by default (`--threads 1-64`).
- Mirrors console results and diagnostics to a UTF-8 file with `--file-output`.

---

## Project Structure

```text
Thestral/
├── README.md
├── docs/
│   └── Plimpy.md
└── Source/
    ├── Thestral.sln
    └── Plimpy/
        ├── Plimpy.vcxproj
        ├── Plimpy.vcxproj.filters
        ├── CMakeLists.txt
        ├── .clang-format
        ├── .editorconfig
        ├── Plimpy.cpp
        ├── ComScanner.cpp / .h
        ├── ConsoleHelper.cpp / .h
        ├── DllUnloader.cpp / .h
        ├── FileMetadata.cpp / .h
        ├── InjectionScanner.cpp / .h
        ├── PeImage.cpp / .h
        ├── ProcessHelper.cpp / .h
        ├── ThreadStack.cpp / .h
        ├── WorkerPool.cpp / .h
        ├── Tests/
        ├── SignatureVerifier.cpp / .h
        ├── UnsignedScanner.cpp / .h
        ├── Handle.h
        ├── WindowsPlatform.h
        ├── App.manifest
        └── App.rc
```

Plimpy is an independent module in the shared Thestral solution. Its console and signature helpers are local to the module.

---

## Usage

Run from an elevated terminal for broader process access. Elevation does not guarantee access to protected processes.

```cmd
Plimpy.exe --help
Plimpy.exe --scan-inject
Plimpy.exe --scan-com
Plimpy.exe --show-signature
Plimpy.exe --scan-inject --scan-com --show-signature
Plimpy.exe --scan-inject --show-signature --threads 8
Plimpy.exe --scan-inject --show-signature --file-output "C:\Reports\Plimpy results.txt"
```

| Option | Purpose |
| --- | --- |
| `-h`, `--help` | Display help. |
| `--scan-inject` | Inspect processes for possible injection and image modification. |
| `--scan-com` | Inspect loaded users' x86 and x64 per-user COM server registrations. |
| `--show-signature` | Report executable images with unverified trust and file metadata. |
| `--threads <count>` | Worker limit for each scan: 1–64, default 5. |
| `--file-output <path>` | Mirror results and diagnostics to a UTF-8 file while keeping console output. |
| `--unload-dll <PID> "<DLL path>"` | Request DLL unloading; cannot be combined with scan options. File output is allowed. |

Quote output paths containing spaces. The parent directory must already exist. Each run creates or overwrites the selected file using UTF-8 without a BOM. If the file cannot be opened, Plimpy reports an error before executing the command. Invalid arguments do not create or truncate files.

`--file-output` can appear before or after the other options and works with `--help` and `--unload-dll`. A file-write failure is reported on the console, console output continues, and the command returns a failure status.

### DLL Unloading

```cmd
Plimpy.exe --unload-dll 1234 "C:\Lab\Example.dll"
Plimpy.exe --unload-dll 1234 "C:\Lab\Example.dll" --file-output "C:\Reports\unload.txt"
```

Use the executable matching the target architecture; cross-architecture requests are rejected. This command modifies the target process and can destabilize it. Use it only on an explicitly selected process after collecting evidence. A successful loader call does not guarantee that a referenced module is fully unmapped.

---

## Workflow

1. **Validate arguments.** Plimpy checks all options before collecting data or opening an output file. Scans use five workers by default; `--threads` sets a limit from 1 to 64. DLL unloading is a separate command. When `--file-output` is selected, Plimpy opens the file before executing the command and mirrors results and diagnostics under the shared output lock.
2. **Attempt debug privilege.** Plimpy attempts to enable `SeDebugPrivilege` before scanning. Access can still be denied for protected processes or registry keys.
3. **Run selected scans.** When multiple scans are requested, they run in this order: injection, COM registrations, then signatures. Each scan discovers its jobs and uses its own worker pool. The scans themselves do not run simultaneously.
4. **Distribute work.** Injection and signature jobs operate on individual processes. COM jobs operate on individual CLSID registrations. Workers claim jobs from an atomic index; the number of workers is the smaller of the configured limit and the number of jobs. `--threads 1` processes jobs sequentially.
5. **Collect findings.** Workers add complete result rows to a shared, locked buffer. Duplicate-path tracking is also locked, while file reads, hashing, registry lookups, and most process checks run independently. All DbgHelp operations are serialized with a separate lock.
6. **Finish and display.** Plimpy joins every worker before printing that scan's table. Rows are sorted by their displayed fields, and columns expand to fit their full values. Each finding occupies one output line without borders or application-inserted wrapping. A narrow terminal can still wrap the displayed line. After the command finishes, Plimpy flushes and closes the optional output file and checks for write errors.

### Injection Scan

`ScanInjection` snapshots processes and threads, groups thread IDs by process, and queues each process for inspection. Each job opens the process, determines its architecture, and enumerates modules. Unsupported architectures are skipped with a diagnostic.

For each available thread, Plimpy queries its Win32 start address. An address outside the module list is checked against the existing memory-protection heuristic. Threads whose start address belongs to an executable module can receive a stack check.

Stack capture takes the DbgHelp lock before suspending the target thread. It reads the appropriate x86, WOW64, or x64 context, walks the stack, restores the original suspend count, and cleans up symbols before releasing the lock. Plimpy excludes its own process. Captured addresses outside the module list can produce suspicious-memory findings.

The process job also compares loaded PE headers and entry-point bytes against the mapped files on disk. Timestamp mismatches and sufficient entry-point byte differences produce heuristic findings. These checks retain the limitations listed below.

### COM Scan

`ScanComRegistrations` collects loaded users' CLSID registrations from both registry views on x64 Windows, or the native view on x86 Windows. Each worker reads a registration's `InprocServer32` default value, expands environment variables, removes surrounding quotes, and resolves system-directory paths for the selected architecture.

Relative paths are searched in the architecture's system directory, with a fallback to the scanner's search context. Paths are deduplicated within each registry view. If signature trust cannot be established, the worker records the view, registry key, and server path.

### Signature Scan

`ScanUnsignedImages` queues processes for architecture-aware inspection. Each job examines the process executable and mapped `MEM_IMAGE` regions, resolves mapped file paths, and claims each unique path for analysis.

`IsFileTrusted` opens the file, checks for catalog membership, and otherwise performs embedded-signature verification through `WinVerifyTrust`. Catalog membership still counts as trusted without catalog-signature verification; this remains a known limitation.

For an unverified file, the worker collects its creation time, owner, PE timestamp, MD5, SHA-1, and SHA-256. One table row contains the process association and all collected metadata. For a file shared by several processes or registrations, the association retained by deduplication depends on which worker claims the path first.

### Worker Errors and DLL Unloading

A worker exception stops the pool from claiming further jobs. Plimpy joins the workers already started, reports the error, and returns a failure status. Individual access failures or disappearing targets can still leave coverage incomplete without failing the whole scan. `No findings reported.` describes collected rows, not proof that every target was inspected.

`--unload-dll` does not use the worker pool. It checks that the executable matches the target architecture, locates the module, starts a target thread at `LdrUnloadDll`, and waits for that thread. Its existing timeout and result-reporting limitations remain documented below.

---

## Example Output

Results use space-aligned columns without vertical borders. Each finding occupies one line, including its full paths and hashes. Repeated letters below stand in for file hashes.

```text
Injection scan
PID         TID         Address             Finding                       Path
----------  ----------  ------------------  ----------------------------  --------------------------------------
1234        -           -                   Entry-point modification      C:\Lab\Example.dll
1234        5678        0x12345000          Suspicious thread             C:\Lab\Example.exe


COM scan
View   Registry key                                                    Server path
-----  --------------------------------------------------------------  ------------------------------------------------
x86    HKEY_USERS\<SID>\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32  C:\Lab\Example.dll


Signature scan
PID         Process                   Created           Owner                     PE timestamp      MD5                               SHA-1                                     SHA-256                                                           Path
----------  ------------------------  ----------------  ------------------------  ----------------  --------------------------------  ----------------------------------------  ----------------------------------------------------------------  --------------------------------------
1234        Example.exe               24/10/2026 13:00  LAB\Analyst               24/10/2026 12:00  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC  C:\Lab\Example.dll
```

Columns expand to fit collected values. Values are not truncated or split across output lines. Missing values appear as `-`, and control characters are escaped. Wide results, especially signature metadata, may wrap visually in a narrow terminal.

Results are buffered until that scan's workers finish, then sorted and printed together. Each selected scan has its own heading.

Save the same one-line records while keeping console output:

```cmd
Plimpy.exe --show-signature --file-output signatures.txt
```

The file contains aligned result tables and diagnostics in UTF-8; it is not CSV. Ordinary shell redirection is also available, but its encoding depends on the shell.

---

## Registry Locations Examined

```text
HKEY_USERS\<loaded user SID>\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32
```

The COM scan uses both registry views on x64 Windows and the native view on x86 Windows. Findings identify the registry view. System-directory paths are resolved for the selected view; an x86 scanner uses the Sysnative alias when accessing native x64 system files. The scan does not enumerate machine-wide registrations, `LocalServer32`, or unloaded user hives.

---

## Threat Hunting Use Cases

- Investigate thread start addresses outside the enumerated module list.
- Review differences between loaded images and their files on disk.
- Investigate per-user COM servers with unverified trust.
- Collect file hashes and ownership information for further analysis.

Correlate findings with process lineage, endpoint telemetry, file reputation, and your environment's software baseline.

---

## Limitations

- An x86 scanner cannot inspect native x64 process memory. Unsupported target architectures are skipped with a diagnostic; use the x64 scanner on x64 Windows.
- Access failures, process exit, and unsupported targets can produce incomplete results. Scan exit codes do not currently distinguish complete from partial coverage.
- Stack inspection remains selective: it is currently triggered for threads whose queried start address belongs to an executable module. It does not capture every thread or reconstruct the native WOW64 transition stack.
- Entry-point comparisons are heuristic and do not account comprehensively for relocations, hotpatching, or legitimate modifications.
- Remote PE inspection assumes headers fit in a 4 KB read.
- Catalog membership currently counts as trusted without verifying the catalog signature. Embedded signatures use `WinVerifyTrust`; explicit revocation checking is disabled.
- Missing or unreadable files are untrusted, but output does not distinguish them from unsigned or invalid files.
- File-path deduplication retains one process or COM registration associated with a file, claimed by the first worker to reach it (COM deduplication is scoped to each registry view).
- Files may change between signature, metadata, and hash reads.
- COM environment expansion uses the scanner's environment. Relative-path fallback resolution does not reproduce every target user's loader context.
- Times are shown in local time without a timezone. A PE timestamp is an unverified header value, not proof of compilation time.
- There are no reputation lookups, JSON export, or baseline comparison features.
- DLL unloading has no timeout and can report a successful command exit even when the loader operation fails.
- Plimpy does not establish a trusted execution environment on an already compromised host.

---

## Code Style

- PascalCase filenames, types, and project functions.
- Descriptive lowerCamelCase local variables and parameters.
- Explicit types; no `auto`, `const auto`, or `auto&` declarations.
- Four-space indentation and Allman braces, enforced by `.clang-format`.
- Wide-character Windows APIs and string output.
- Small implementation/header pairs and the `Plimpy` namespace.
- `Handle` owns ordinary Windows handles; other resource types use their matching release APIs.

Plimpy keeps its own signature-verification implementation. Its behavior and limitations differ from the signature helpers in other Thestral modules.

---

## Future Enhancements

- Verified catalog signatures and explicit verification statuses.
- Broader stack coverage and native x86 Windows validation.
- Structured output and scan-coverage summaries.
- Expanded COM registration coverage.
- Stronger PE validation and file identity tracking.
- Additional regression tests and Windows CI.

---

## Intended Audience

- Threat hunters.
- Incident responders and DFIR analysts.
- Malware researchers.
- Windows security engineers.

---

## Disclaimer

Plimpy is intended for authorized defensive analysis. Suspicious findings are investigative leads and do not establish that a process or file is malicious.
