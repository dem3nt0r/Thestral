# Thestral

**Thestral** is a modular Windows threat hunting toolkit focused on helping defenders identify, investigate, and analyze common persistence mechanisms, execution chains, and system components that may be abused by attackers.

Rather than relying solely on Indicators of Compromise (IOCs), Thestral emphasizes inspecting Windows internals, validating trust relationships, and identifying suspicious configurations that can reveal attacker activity or persistence.

Each module is designed to operate independently, allowing security professionals to use only the tools relevant to their investigation while maintaining a consistent workflow across the toolkit.

---

# Modules

| Project           | Description                                                                                                                                                                                            | Documentation                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| **TaskHunter**    | Enumerates Windows Scheduled Tasks and analyzes COM Handler actions. Resolves COM CLSIDs, identifies backing DLLs, and validates Authenticode signatures to detect suspicious persistence mechanisms.  | [TaskHunter Documentation](docs/TaskHunter.md)       |
| **SvcHostHunter** | Enumerates services hosted by **svchost.exe**, resolves **ServiceDll** modules, verifies Authenticode signatures, extracts signer information, and highlights suspicious or non-standard service DLLs. | [SvcHostHunter Documentation](docs/SvcHostHunter.md) |
| **RIDHunter**     | Analyzes local account information from the Windows SAM database to detect potential RID Hijacking by comparing account RID mappings and embedded RID data. Reports suspicious RID mismatches for DFIR and threat hunting investigations. | [RIDHunter Documentation](docs/RIDHunter.md)

---

# Current Capabilities

The Thestral toolkit currently provides hunting capabilities for:

* Windows Scheduled Tasks
* COM Handler persistence
* Service DLL auditing
* Authenticode signature validation
* Catalog signature verification
* Microsoft vs. third-party signer identification
* Windows persistence analysis

---

# Design Goals

* Threat hunting first
* Modular architecture with independent tools
* Lightweight native C++ implementation
* Minimal dependencies
* Fast execution suitable for enterprise environments
* Clear visibility into Windows persistence mechanisms
* Support for DFIR and incident response workflows
* Easy integration into automation and scripting pipelines

---

# Planned Modules

The toolkit is designed to grow over time. Planned modules include:

* RegistryHunter
* ServiceHunter
* DriverHunter
* COMHunter
* WMIHunter
* StartupHunter
* IFEOHunter
* LSAHunter
* AppInitHunter
* WinlogonHunter

---

# Intended Audience

Thestral is intended for:

* Threat Hunters
* Blue Team Analysts
* Incident Responders (IR)
* Digital Forensics (DFIR) Practitioners
* Detection Engineers
* Windows Security Researchers
* Enterprise Security Teams

---

# Contributing

Contributions are welcome.

If you would like to improve Thestral, you can:

* Report bugs
* Submit pull requests
* Suggest new hunting modules
* Improve existing detection logic
* Enhance performance or documentation

Please follow the existing coding style and include a clear description of any proposed changes.

---

# License

MIT License.

See the `LICENSE` file for details.

---

# Disclaimer

Thestral is intended solely for defensive security, threat hunting, digital forensics, and incident response on systems for which you have explicit authorization.

The project is provided for research and educational purposes. Users are responsible for ensuring compliance with all applicable laws, regulations, and organizational policies.
