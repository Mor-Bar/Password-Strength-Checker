# 🔐 Password Strength Checker 🔐

A comprehensive, professional-grade password security analysis tool built with Python. Features modular architecture, entropy calculation, pattern detection, common password database validation, and real-time breach checking via "Have I Been Pwned" API.

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-professional-brightgreen.svg)]()

---

## Table of Contents

- [Features](#-features)
- [Demo](#-demo)
- [Installation](#-installation)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Technical Details](#-technical-details)
- [Security & Privacy](#-security--privacy)
- [Project Structure](#-project-structure)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## Features

### Core Analysis Engine
- **Character Validation**: Comprehensive checks for uppercase, lowercase, digits, and special characters
- **Shannon Entropy Calculation**: Mathematical randomness analysis with detailed entropy scoring
- **Pattern Detection**: Identifies sequential characters, repeated patterns, common years, and keyboard patterns
- **Common Password Database**: Validates against 100+ most commonly used passwords worldwide
- **Data Breach Detection**: Real-time checking via Have I Been Pwned API (52M+ breached passwords)
- **Smart Recommendations**: Context-aware suggestions for password improvement

### Advanced Features
- **Weighted Scoring System**: Industry-standard point allocation (0-100 scale)
- **Dynamic Penalty System**: Severity-based penalties for weak patterns and breaches
- **k-Anonymity Model**: Privacy-preserving breach checks (never transmits full password/hash)
- **Color-Coded Output**: Professional terminal UI with ANSI color support
- **Modular Architecture**: Clean separation of concerns for maintainability and testing

### Security Checks Breakdown
| Check Type | Points | Description |
|------------|--------|-------------|
| Length | 0-30 | Password length scoring (min 8, recommended 12+) |
| Uppercase | 0-15 | Presence of A-Z characters |
| Lowercase | 0-15 | Presence of a-z characters |
| Digits | 0-20 | Presence of 0-9 numbers |
| Special Chars | 0-20 | Presence of punctuation/symbols |

### Pattern Penalties
| Pattern Type | Penalty | Examples |
|--------------|---------|----------|
| Sequential Chars | -10 | abc, 123, xyz |
| Repeated Chars | -10 | aaa, 111, !!! |
| Common Years | -5 | 1990, 2024 |
| Keyboard Patterns | -15 | qwerty, asdfgh, 12345 |
| Common Password | -50 | password, admin, 123456 |
| Data Breach | -25 to -40 | Based on breach count severity |

---

## Demo

### Strong Password Example
```
Enter password to check: MyP@ssw0rd!X9

Security Checks:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[PASS] Length         (25/30 pts) - Password length good: 13 characters
[PASS] Uppercase      (15/15 pts) - Contains uppercase letters (3 found)
[PASS] Lowercase      (15/15 pts) - Contains lowercase letters (6 found)
[PASS] Digits         (20/20 pts) - Contains numeric digits (2 found)
[PASS] Special Chars  (20/20 pts) - Contains special characters (2 found)

Base Score: 95/100

Entropy Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Entropy: 85.21 bits - Very High

Common Password Check:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[PASS] Password not found in common passwords database

Data Breach Check (Have I Been Pwned):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[PASS] Password not found in known data breaches

Final Score: 95/100
Strength: VERY STRONG
[████████████████████████████████████████████████  ]
```

### Weak Password Example
```
Enter password to check: password

Security Checks:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[PASS] Length         (15/30 pts) - Password length acceptable: 8 characters
[FAIL] Uppercase       (0/15 pts) - Missing uppercase letters (A-Z)
[PASS] Lowercase      (15/15 pts) - Contains lowercase letters (8 found)
[FAIL] Digits          (0/20 pts) - Missing numeric digits (0-9)
[FAIL] Special Chars   (0/20 pts) - Missing special characters (!"#$%&'()*)

Base Score: 30/100

Entropy Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Entropy: 37.6 bits - Moderate

Common Password Check:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[CRITICAL] Password found in common passwords database - HIGH RISK

Data Breach Check (Have I Been Pwned):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[CRITICAL] Password found in 52,256,179 data breaches - CRITICAL RISK

Weak Patterns Detected:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[WARN] Keyboard Pattern: 'password' (-15 pts)
[WARN] Common Password: '***' (-50 pts)
[WARN] Data Breach Exposure: '52,256,179 breaches' (-40 pts)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Penalty: -105 points

Final Score: 0/100
Strength: VERY WEAK
[                                                  ]

Recommendations for Improvement:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1] Add uppercase letters (A-Z)
[2] Add numeric digits (0-9)
[3] Add special characters (!@#$%^&*)
[4] Avoid predictable patterns (sequential chars, repetition, common words)
[5] CRITICAL: Never use common passwords - this one is in the top 10,000
[6] CRITICAL: Password exposed in 52,256,179 data breaches - change immediately
[7] Increase randomness - use a mix of unrelated characters
```

---

## Installation

### Prerequisites
- Python 3.11 or higher
- pip (Python package manager)

### Clone the Repository
```bash
git clone https://github.com/Mor-Bar/Password-Strength-Checker.git
cd Password-Strength-Checker
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Verify Installation
```bash
python -m src
```

---

## Usage

### Basic Usage
```bash
python -m src
```

### Interactive Mode
The tool runs in interactive mode by default:
1. Enter a password when prompted
2. View comprehensive analysis results
3. Review recommendations (if applicable)
4. Type `exit` or press `Ctrl+C` to quit

### Example Session
```bash
$ python -m src

======================================================================
Password Strength Checker
Version 0.3.0 - Modular Refactoring
======================================================================
Type 'exit' or press Ctrl+C to quit
======================================================================

Enter password to check: MySecureP@ssw0rd2024!

[Analysis results displayed here...]

Enter password to check: exit

======================================================================
Thank you for using Password Strength Checker!
======================================================================
```

---

## Architecture

### Modular Design Philosophy
The project follows a clean, modular architecture with separation of concerns:
```
Password Strength Checker
│
├── Configuration Layer (config.py)
│   └── Constants, thresholds, API settings
│
├── Validation Layer (validators.py)
│   └── Character-based security checks
│
├── Analysis Layer (analyzers.py)
│   └── Entropy calculation, pattern detection
│
├── Extension Layer (checker.py)
│   └── Common passwords, breach checking, recommendations
│
├── Presentation Layer (display.py)
│   └── User interface, formatted output
│
└── Orchestration Layer (password_checker.py)
    └── Main application logic, workflow coordination
```

### Data Flow
```
User Input → Validators → Analyzers → Checker → Scoring → Display → User
              ↓              ↓          ↓          ↓
           config.py     config.py  HIBP API   config.py
```

---

## Technical Details

### Entropy Calculation
Uses Shannon entropy formula to measure password randomness:
```
H = L × log₂(N)

Where:
- H = Entropy in bits
- L = Password length
- N = Character pool size
```

**Character Pool Calculation:**
- Lowercase (a-z): +26
- Uppercase (A-Z): +26
- Digits (0-9): +10
- Special chars: +32

**Entropy Ratings:**
- < 28 bits: Very Low (crackable in seconds)
- 28-35 bits: Low (crackable in minutes/hours)
- 36-59 bits: Moderate (crackable in days/weeks)
- 60-79 bits: High (crackable in months/years)
- 80+ bits: Very High (computationally infeasible)

### Pattern Detection Algorithms

#### Sequential Characters
Detects alphabetic (abc, xyz) and numeric (123, 789) sequences:
```python
# Check consecutive characters for sequential patterns
for i in range(len(password) - 2):
    if ord(char2) == ord(char1) + 1 and ord(char3) == ord(char2) + 1:
        # Sequential pattern detected
```

#### Repeated Characters
Uses regex to identify character repetition (3+ times):
```python
pattern = r'(.)\1{2,}'  # Matches any character repeated 3+ times
```

#### Keyboard Patterns
Matches against predefined keyboard layout sequences:
- QWERTY rows: qwerty, asdfgh, zxcvbn
- Number rows: 12345, 67890
- Common combinations: qwertyuiop, asdfghjkl

### Have I Been Pwned Integration

#### k-Anonymity Model
Implements privacy-preserving password breach checking:

1. **Hash Password**: Compute SHA-1 hash of password
2. **Split Hash**: Take first 5 characters as prefix
3. **Query API**: Send only the 5-character prefix
4. **Receive Results**: API returns ~500 hash suffixes matching prefix
5. **Local Matching**: Check if full hash exists in results

**Privacy Guarantee**: Neither the password nor its full hash ever leaves the client.

#### API Details
- **Endpoint**: `https://api.pwnedpasswords.com/range/{hash_prefix}`
- **Method**: GET
- **Response Format**: `{hash_suffix}:{count}\r\n`
- **Timeout**: 5 seconds
- **Error Handling**: Graceful degradation on network failures

---

## Security & Privacy

### Privacy Protections
- **No Data Storage**: Passwords are never stored or logged
- **k-Anonymity**: Breach checks use hash prefix only (5 chars of SHA-1)
- **Local Processing**: All analysis done client-side
- **No Telemetry**: No usage data transmitted

### Security Best Practices
- Input validation and sanitization
- Timeout protection for API calls
- Error handling for all external operations
- No shell command execution
- No file system access beyond data directory

---

## Project Structure
```
Password-Strength-Checker/
│
├── src/                          # Source code
│   ├── __init__.py              # Package initializer
│   ├── __main__.py              # Entry point
│   ├── config.py                # Configuration and constants
│   ├── validators.py            # Character validation logic
│   ├── analyzers.py             # Entropy and pattern detection
│   ├── checker.py               # Common passwords, HIBP, recommendations
│   ├── display.py               # User interface and output
│   └── password_checker.py      # Main orchestration logic
│
├── data/                         # Data files
│   └── common_passwords.txt     # Common passwords database
│
├── tests/                        # Unit tests (future)
│
├── requirements.txt              # Python dependencies
├── README.md                     # This file
├── LICENSE                       # MIT License
└── .gitignore                   # Git ignore rules
```

---

## Roadmap

### Version 0.4.0 - Testing & Validation
- [ ] Unit tests for all modules
- [ ] Integration tests
- [ ] Performance benchmarks
- [ ] Code coverage reports

### Version 0.5.0 - Enhanced Features
- [ ] Expand common passwords database to 10,000+
- [ ] Dictionary word detection
- [ ] Language-specific character analysis
- [ ] Password generation with customizable rules

### Version 0.6.0 - Advanced Analysis
- [ ] Machine learning-based strength prediction
- [ ] Markov chain analysis for predictability
- [ ] Zxcvbn-style pattern matching
- [ ] Custom rule definitions

### Version 1.0.0 - Production Ready
- [ ] GUI interface (Tkinter/PyQt)
- [ ] REST API wrapper
- [ ] Docker containerization
- [ ] Comprehensive documentation
- [ ] Security audit

---

## 🤝 Contributing 🤝

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/AmazingFeature`
3. **Commit your changes**: `git commit -m 'Add some AmazingFeature'`
4. **Push to the branch**: `git push origin feature/AmazingFeature`
5. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include type hints
- Write unit tests for new features
- Update README if needed

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Mor**
- Software Engineering Graduate (SCE) - Cybersecurity Specialization
- MBA Student - Technology & Information Management (Tel Aviv University)

### Connect
- GitHub: (https://github.com/Mor-Bar)
- LinkedIn: (https://www.linkedin.com/in/morbar/)

---

## Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com/) - For the excellent breach detection API
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Password guidelines
- Python Community - For amazing tools and libraries

---

<div align="center">

**⭐ If you found this project helpful, please consider giving it a star! ⭐**

Made with ❤️ and Python

</div>