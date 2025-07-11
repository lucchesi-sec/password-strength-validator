# Password Strength Validator

![Python](https://img.shields.io/badge/Python-3.6+-blue) ![Security](https://img.shields.io/badge/Security-Password%20Analysis-red) ![NIST](https://img.shields.io/badge/Standard-NIST%20SP%20800--63B-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

A comprehensive password strength analysis tool that evaluates passwords against NIST SP 800-63B and OWASP guidelines. The analyzer provides detailed security assessments with entropy calculations, pattern detection, and specific recommendations for improvement.

## 🔒 Security Impact

This project demonstrates critical password security principles:
- **Security Assessment**: Systematic evaluation of password strength and vulnerabilities
- **Compliance Validation**: NIST SP 800-63B and OWASP guideline adherence
- **Risk Analysis**: Identification of common attack vectors and weaknesses
- **Security Education**: Teaching secure password practices through analysis

### Analysis Workflow
```mermaid
graph TD
    A[Password Input] -->|\"Secure Processing\"| B[Multi-Factor Analysis]
    B --> C[Length & Complexity]
    B --> D[Entropy Calculation]
    B --> E[Pattern Detection]
    C --> F[Security Score]
    D --> F
    E --> F
    F --> G[Recommendations]
```

## 🛡️ Cybersecurity Relevance

1. **Authentication Security**: Strengthens the first line of defense in access control
2. **Risk Assessment**: Identifies password vulnerabilities before they're exploited
3. **Compliance Support**: Helps organizations meet security standards and regulations
4. **Security Awareness**: Educates users on password security best practices

## ⚠️ Privacy Notice

**All analysis is performed locally** - passwords are never transmitted over networks, stored persistently, or logged. The tool uses secure input methods and follows privacy-by-design principles.

## 🛠️ Features

### Core Analysis Capabilities
- **Strength Scoring**: Overall security score (0-100) with detailed breakdown
- **Entropy Calculation**: Measures password randomness in bits
- **Pattern Detection**: Identifies common vulnerabilities and attack patterns
- **Dictionary Checks**: Validates against breach lists and common passwords
- **Compliance Assessment**: NIST SP 800-63B and OWASP guideline evaluation

### Security Checks
- **Length Analysis**: Enforces minimum requirements with bonuses for longer passwords
- **Complexity Verification**: Character variety and distribution analysis
- **Vulnerability Detection**: Common attack patterns including:
  - Dictionary words and common passwords
  - Keyboard sequences (qwerty, 12345)
  - Repeated characters and patterns
  - Date formats and years
  - Leet speak substitutions (p4ssw0rd, l33t)

### User Experience
- **Interactive CLI**: Full-featured command-line interface with color output
- **Batch Analysis**: Compare multiple passwords simultaneously
- **Report Generation**: Detailed JSON reports for documentation
- **Password Generation**: Create cryptographically strong passwords
- **Security Recommendations**: Specific guidance for improvement

## 📋 Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)
- Terminal with color support (optional, fallback available)

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/lucchesi-sec/password-strength-validator.git
cd password-strength-validator
```

2. No additional dependencies required - ready to use!

## 💻 Usage

### Quick Analysis

```bash
# Basic password analysis (secure prompt)
python src/password_analyzer.py

# Direct password input (not recommended - visible in shell history)
python src/password_analyzer.py --password \"YourPassword123!\"

# Save detailed report
python src/password_analyzer.py --output analysis_report.json

# Quiet mode (JSON output only)
python src/password_analyzer.py --output report.json --quiet
```

### Interactive CLI Interface

```bash
# Launch full interactive interface
python src/cli.py

# Or use the main entry point
python analyze.py --cli
```

The interactive CLI provides:
- Menu-driven password analysis
- Password generation with strength verification
- Multiple password comparison
- Report saving and management
- Help and guidance

### Example Analysis Output

```
══════════════════════════════════════════════════════════
PASSWORD STRENGTH: STRONG
══════════════════════════════════════════════════════════

Overall Score: 82.5/100
Length: 14 characters
Entropy: 76.85 bits
Complexity Score: 95/100
Pattern Safety Score: 70/100

ISSUES DETECTED:
• Contains dictionary word 'password'

RECOMMENDATIONS:
• Avoid using dictionary words
• Consider increasing length to 16+ characters
```

## 📁 Project Structure

```
password-strength-validator/
├── src/
│   ├── password_analyzer.py  # Core analysis engine
│   └── cli.py               # Interactive CLI interface
├── data/
│   ├── common_passwords.txt # Known breached passwords
│   └── english_words.txt    # Dictionary word list
├── tests/
│   └── test_analyzer.py     # Test suite
├── analyze.py               # Main entry point
└── README.md               # This file
```

## 🔧 Technical Details

### Scoring Methodology

The overall password strength score uses a weighted combination:

1. **Entropy (50%)**: Measures randomness based on character set and length
2. **Complexity (30%)**: Evaluates character variety and distribution  
3. **Pattern Safety (20%)**: Penalizes common patterns and vulnerabilities

Each component is scored 0-100 and weighted to produce the final score.

### Security Standards Compliance

- **NIST SP 800-63B**: Length requirements, composition rules, and blacklist checking
- **OWASP**: Authentication guidelines and password storage recommendations
- **Privacy by Design**: Local processing with no data transmission or storage

### Entropy Calculation

Entropy is calculated using the formula: `H = L × log₂(R)`
- H: Entropy in bits
- L: Password length
- R: Character pool size (based on character classes used)

## 📊 Strength Categories

| Score Range | Category | Description |
|-------------|----------|-------------|
| 90-100 | Very Strong | Excellent security, minimal risk |
| 70-89 | Strong | Good security, low risk |
| 50-69 | Moderate | Acceptable security, moderate risk |
| 25-49 | Weak | Poor security, high risk |
| 0-24 | Very Weak | Unacceptable security, very high risk |

## 🔒 Customization

### Extending Dictionaries

Enhance detection by expanding wordlists:

1. **Common Passwords** (`data/common_passwords.txt`):
   - Add passwords from recent breach lists
   - Include organization-specific common passwords
   - One password per line, case-insensitive

2. **Dictionary Words** (`data/english_words.txt`):
   - Add language-specific dictionaries
   - Include technical terms and slang
   - Consider industry-specific vocabularies

### Configuration

The analyzer can be customized by modifying constants in `password_analyzer.py`:

```python
MIN_LENGTH = 8              # Minimum acceptable length
RECOMMENDED_LENGTH = 12     # Recommended minimum length
ENTROPY_WEIGHT = 0.5        # Entropy component weight
COMPLEXITY_WEIGHT = 0.3     # Complexity component weight
PATTERN_WEIGHT = 0.2        # Pattern safety weight
```

## 🧪 Testing

Run the test suite to verify functionality:

```bash
python -m pytest tests/ -v
```

## 📚 Security References

- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/) (Password breach research)
- [Password Security Research](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler)

## 🔒 License

MIT License - see LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and assessment purposes. While it follows current security best practices, password security is just one component of comprehensive authentication security. Consider implementing multi-factor authentication and other security controls as part of a complete security strategy.