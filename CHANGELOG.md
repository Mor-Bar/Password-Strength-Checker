# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-03

### Added
- Modular architecture with separation of concerns
- Common passwords database (100+ passwords)
- Have I Been Pwned API integration with k-anonymity
- Smart recommendations engine
- Dynamic penalty system based on severity
- Professional README with comprehensive documentation
- MIT License

### Changed
- Refactored monolithic codebase into 7 modules
- Improved error handling and user feedback
- Enhanced UI with color-coded output

### Technical
- New modules: config.py, validators.py, analyzers.py, checker.py, display.py
- API integration with requests library
- Privacy-preserving breach checking

## [0.2.0] - 2026-01-02

### Added
- Shannon entropy calculation
- Pattern detection (sequential, repeated, years, keyboard)
- Penalty system for weak patterns
- Weighted scoring system
- Visual progress bars

### Changed
- Enhanced scoring algorithm with penalties
- Improved output formatting

## [0.1.0] - 2026-01-01

### Added
- Initial release
- Basic character validation (length, uppercase, lowercase, digits, special)
- Simple scoring system (0-100)
- Strength categories
- Color-coded terminal output
- Interactive CLI interface

---

## Version History Summary

- **0.3.0** - Modular Refactoring + Advanced Features
- **0.2.0** - Entropy & Pattern Detection
- **0.1.0** - Initial Release
