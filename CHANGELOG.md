# Changelog

All notable changes to APKX-Hunter are documented in this file.

---

## [2.7.1] 

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
