# Thestral

Thestral is a threat hunting focused project that groups a set of specialized Windows security tools designed to help detect, investigate, and analyze common persistence and execution techniques used by adversaries.

The project is structured as a modular toolkit, where each component focuses on a specific attack surface such as Scheduled Tasks, COM objects, registry persistence, or execution chains. This design allows each tool to be used independently during incident response or combined for broader investigations.

---

## Modules

| Project | Description | Documentation |
|----------|-----------------------------|-----------------------------|
| TaskHunter | Enumerates Windows Scheduled Tasks and analyzes COM Handler actions. It extracts COM CLSIDs, resolves backing DLLs, and verifies Authenticode signatures to detect suspicious or unsigned persistence mechanisms. | [TaskHunter Documentation](./TaskHunter/TaskHunter.md) |

---

## Focus Areas

Thestral focuses on threat hunting across Windows environments, including:

- Persistence mechanisms
- COM-based execution paths
- Scheduled Task abuse
- Signed vs unsigned binary analysis
- Hidden or less visible execution chains

---

## Design Goals

- Security research and threat hunting first
- Modular architecture with independent tools
- Lightweight and fast execution
- Clear visibility into Windows persistence mechanisms
- Support for DFIR workflows

---

## Usage

Each tool inside Thestral is a standalone module. Refer to the individual module documentation for details on usage, output, and analysis scope.

---

## Disclaimer

Thestral is intended strictly for defensive security, threat hunting, and incident response activities. It should only be used in systems and environments where proper authorization has been granted.
```