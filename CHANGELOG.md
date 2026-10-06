# Changelog

All notable changes to APKX-Hunter are documented in this file.
---

## Apkx-Hunter [3.0.0]

**APKX-Hunter v3.0.0** introduces a major framework upgrade, expanding APKX-Hunter from an Android static-analysis tool into a more complete **interactive Android Application Static security analysis framework**.

### Added

* **Interactive Shell Integration** — Added a dedicated command-line shell for interacting with APKX-Hunter directly from the terminal.
* **Code Search & Investigation** — Added recursive code searching across decompiled applications and project directories.
* **Code Context Analysis** — Search results provide file paths, line numbers, matching source lines, and surrounding code context.
* **Categorized MASVS Findings** — MASVS security findings are now organized into dedicated security categories for easier investigation and reporting.
* **Structured Analysis Output** — Improved organization of generated findings and analysis results into clear output categories.
* **Interactive Framework Commands** — Added framework-level commands for analysis execution, help, terminal control, banner display, and exiting the framework.
* **Quiet No Output On Terminal Mode** — Added improved control over normal framework output during automated and batch workflows.
* **Improved Scan Statistics** — Enhanced scan statistics and final analysis summaries.

---
---
---

## Apkx-Hunter [2.7.2]

### Added
* APKX Hunter now checks the installed JADX and Apktool versions against the required minimum versions before starting a scan.
* Scanning is stopped when an incompatible dependency version is detected, with a message instructing the user to update the required tool.

### Fixed
* Fixed an Apktool 3.0.3 compatibility issue where APKX Hunter constructed the decode command with the -f option in the wrong position.
* Corrected the Apktool decode command to use the proper argument ordering.

---
---
---

## Apkx-Hunter [2.7.1] 

### Fixed

* Fixed `model.bin` path resolution and loading issues.
* Fixed model loading failures caused by incorrect model file placement.
* Fixed repeated model-loading failures during large APK scans.
* Fixed AI model initialization issues after the source-code restructuring.
* Fixed linker errors related to model and model-path symbols.
* Fixed malformed ANSI terminal escape sequences in scan output.
* Fixed missing return statements in multiple non-void functions.
* Improved logical-expression clarity to address compiler warnings.
* Fixed build and packaging issues affecting the final binary.

---
---
---

## APKX-Hunter v2.7.0

### Added
- Introduced a modular framework architecture for improved scalability.

### Changed
- Completely restructured the project into a professional multi-file framework.
- Improved separation of source (`.c`) and header (`.h`) files.
- Refactored internal modules for better maintainability and readability.
- Simplified dependency management between framework components.
- Improved the build process for easier compilation and packaging.

### Fixed
- Fixed multiple linker and compilation issues.
- Resolved duplicate symbol and `extern` declaration problems.
- Fixed internal dependency and include-related issues.
- Improved overall framework stability and reliability.

### Performance
- Reduced code coupling between modules.
- Improved maintainability for future feature development.
- Prepared the framework for easier expansion and long-term support.


---
---
---

## v2.6.0 

### Major Release – Native Debian Package Support

### Added

- Native Debian package (`.deb`) distribution.
- Desktop launcher integration.
- Application menu integration.
- Custom application icon.
- System-wide installation support.
- Automatic framework asset installation.
- Built-in dependency manager:
  ```bash
  apkxhunter --install-dependencies
  ```
- Improved Linux deployment workflow.
- Enhanced installation documentation.

---

### 🔄 Changed

- Removed the legacy **install.sh** installer.
- Replaced the Bash-based dependency installation workflow with a fully integrated C-based dependency management system.
- Improved Debian package structure.
- Improved Linux filesystem integration.

---
---
---

## v2.5.1

- Added AI model validation.
- Added startup model availability checks.
- Improved Secret Detection initialization.
- Prepared framework for future Debian packaging.
