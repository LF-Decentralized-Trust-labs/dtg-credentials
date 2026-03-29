# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `DTGCredential::sign()` is now an `async` method (breaking change) to align with upstream `affinidi-data-integrity` v0.5
- Updated `affinidi-data-integrity` dependency from 0.4 to 0.5
- Updated `affinidi-tdk` dev-dependency from 0.5 to 0.6
- Relaxed `tokio` dev-dependency version from 1.49 to 1
- Updated repository URL to `https://github.com/OpenVTC/dtg-credentials`
- Enabled crate publishing (`publish = true`)

## [0.1.1] - 2025-01-01

### Changed

- Updated Affinidi dependencies to latest versions

## [0.1.0] - 2025-01-01

### Added

- Initial release
- Support for W3C VC 1.1 and 2.0 specifications
- DTG credential types: VMC, VRC, VIC, VPC, VEC, VWC, and RCard
- Credential signing via W3C Data Integrity Proof (JCS EdDSA 2022)
- Credential verification with public key bytes
- Optional `affinidi-signing` feature for integrated signing support
