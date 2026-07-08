# TaskHunter

TaskHunter is a Windows security analysis tool designed to enumerate all Scheduled Tasks on a system and identify tasks that use **COM Handler Actions**. For each COM handler, the tool resolves the associated CLSID, locates the associated DLL, and validates its Authenticode digital signature.

The tool is intended for **threat hunting**, **incident response**, **persistence detection**, and **Windows security auditing** where attackers may abuse COM-based scheduled tasks to execute malicious code.

---

## Features

- Enumerates all Scheduled Tasks, including hidden tasks.
- Recursively traverses all Task Scheduler folders.
- Identifies task action types:
  - EXEC actions
  - COM Handler actions
  - Other action types
- Resolves COM Handler CLSIDs.
- Extracts COM DLL paths from the registry.
- Verifies Authenticode digital signatures of COM DLLs.
- Displays:
  - Certificate thumbprint/hash
  - Publisher name
  - Signature validation status
- Detects COM objects configured with `DllSurrogate`.
- Helps identify suspicious, unsigned, or untrusted COM components used by scheduled tasks.

---

## Why TaskHunter?

Scheduled Tasks are one of the most common persistence mechanisms used by attackers.

While defenders often inspect tasks that launch executables directly, COM Handler Tasks are frequently overlooked because they execute code through a registered COM object rather than a visible executable path.

A typical abuse scenario may involve:

1. Registering a malicious COM object.
2. Creating a Scheduled Task that uses a COM Handler Action.
3. Configuring the task to trigger at logon, startup, or on a schedule.
4. Allowing Task Scheduler to load the COM object automatically.

Since the task itself may not reference a suspicious executable, COM-based persistence can evade basic task reviews.

TaskHunter helps analysts quickly:

- Discover COM Handler Tasks.
- Locate the backing DLL.
- Verify digital signatures.
- Identify suspicious publishers.
- Detect unsigned persistence mechanisms.

---

## Usage

Run from an elevated command prompt:

```cmd
TaskHunter.exe
```

No command-line arguments are required.

---

## Example Output

```text
==================================================
Task Name: Example Task
Task Path: \Microsoft\Windows\Example

[COM HANDLER ACTION]

    CLSID: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}

    DLL: C:\Windows\System32\example.dll

    Signature: VALID
      Cert Hash: ABCDEF1234567890...
      Publisher: Microsoft Windows

    AppID: {YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYYY}
    Uses DLLHOST.EXE (DllSurrogate present)
    DllSurrogate: <default dllhost>
```

---

## Registry Locations Examined

### CLSID Registration

```text
HKCR\CLSID\<CLSID>
```

### COM Server Registration

```text
HKCR\CLSID\<CLSID>\InprocServer32
```

### AppID Configuration

```text
HKCR\AppID\<AppID>
```

---

## Threat Hunting Use Cases

### Unsigned COM DLLs

Look for:

```text
Signature: INVALID or UNSIGNED
```

Unsigned DLLs associated with scheduled tasks should be investigated.

### Unexpected Publishers

Review DLLs signed by:

- Unknown vendors
- Newly issued certificates
- Publishers uncommon within your environment

### User-Writable Locations

Examples include:

```text
C:\Users\<user>\AppData\
C:\ProgramData\
C:\Temp\
```

COM DLLs loaded from user-writable locations may indicate persistence or malicious activity.

### DLLHOST-Based Execution

Tasks associated with:

```text
DllSurrogate
```

execute through:

```text
dllhost.exe
```

This can complicate process lineage analysis and may be abused to obscure execution.

### Hidden Scheduled Tasks

TaskHunter enumerates hidden tasks, allowing analysts to inspect task entries that may not be immediately visible in the Task Scheduler GUI.

---

## Detection Opportunities

TaskHunter can help security teams:

- Establish baselines of legitimate COM Handler Tasks.
- Identify newly introduced COM registrations.
- Detect unsigned persistence mechanisms.
- Correlate suspicious DLLs with scheduled execution.
- Validate trust chains during incident response investigations.

---

## Limitations

- Verifies Authenticode signatures only.
- Does not perform reputation checks.
- Does not query external threat intelligence sources.
- Does not currently export results to CSV or JSON.
- COM registrations requiring elevated permissions may not be fully accessible.

---

## Future Enhancements

- CSV export
- JSON export
- SHA1/SHA256 hash calculation
- Certificate chain analysis
- VirusTotal integration
- Detection of orphaned CLSIDs
- Detection of missing COM DLLs
- YARA scanning support
- Baseline comparison mode

---

## Intended Audience

- Threat Hunters
- DFIR Analysts
- Incident Responders
- Malware Researchers
- Blue Team Operators
- Windows Security Engineers

---

## Disclaimer

TaskHunter is intended for defensive security, threat hunting, incident response, and system auditing purposes. Legitimate software may also use COM Handler Tasks and DLL Surrogates, so findings should always be validated before drawing conclusions.