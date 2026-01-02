"""
Configuration and Constants
===========================
Central configuration file containing all constants, thresholds,
and configuration values used throughout the application.

This separation allows for easy modification of settings without
touching the core logic.
"""

import string

# ============================================================================
# PASSWORD LENGTH REQUIREMENTS
# ============================================================================

# Minimum acceptable password length
MIN_PASSWORD_LENGTH = 8

# Recommended password length for strong security
RECOMMENDED_PASSWORD_LENGTH = 12


# ============================================================================
# CHARACTER SETS
# ============================================================================

# Character sets for validation (from string module)
UPPERCASE_CHARS = string.ascii_uppercase      # A-Z
LOWERCASE_CHARS = string.ascii_lowercase      # a-z
DIGIT_CHARS = string.digits                   # 0-9
SPECIAL_CHARS = string.punctuation            # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~


# ============================================================================
# SCORING SYSTEM
# ============================================================================

# Point allocation for each validation check (total: 100)
SCORE_WEIGHTS = {
    'length': 30,           # 30 points for adequate length
    'uppercase': 15,        # 15 points for uppercase letters
    'lowercase': 15,        # 15 points for lowercase letters
    'digits': 20,           # 20 points for numeric digits
    'special': 20           # 20 points for special characters
}

# Penalty points deducted for detected weak patterns
PATTERN_PENALTIES = {
    'sequential': 10,       # Sequential characters (abc, 123)
    'repeated': 10,         # Repeated characters (aaa, 111)
    'common_year': 5,       # Common year patterns (2024, 1990)
    'keyboard_pattern': 15  # Keyboard patterns (qwerty, asdfgh)
}


# ============================================================================
# STRENGTH THRESHOLDS
# ============================================================================

# Score ranges for password strength classification
SCORE_THRESHOLDS = {
    'very_weak': 20,        # 0-19: Very weak
    'weak': 40,             # 20-39: Weak
    'moderate': 60,         # 40-59: Moderate
    'strong': 80,           # 60-79: Strong
    'very_strong': 100      # 80-100: Very strong
}

# Entropy thresholds (in bits) for classification
ENTROPY_THRESHOLDS = {
    'very_low': 28,         # < 28 bits: Very low
    'low': 36,              # 28-35 bits: Low
    'moderate': 60,         # 36-59 bits: Moderate
    'high': 80,             # 60-79 bits: High
    'very_high': 100        # 80+ bits: Very high
}


# ============================================================================
# PATTERN DETECTION
# ============================================================================

# Known weak keyboard patterns to detect
KEYBOARD_PATTERNS = [
    # QWERTY keyboard rows
    'qwerty', 'qwertz', 'qwerti', 'qwertyu',
    'asdfgh', 'asdfghjkl',
    'zxcvbn', 'zxcvbnm',
    
    # Sequential numbers
    '12345', '123456', '1234567', '12345678',
    '01234', '234567', '345678', '456789',
    
    # Common weak patterns
    'abcdef', 'abcdefg',
    'password', 'passwd', 'admin', 'letmein'
]


# ============================================================================
# ANSI COLOR CODES
# ============================================================================

class Colors:
    """
    ANSI escape codes for colored terminal output.
    
    These codes work on Unix/Linux/Mac terminals and Windows 10+ Command Prompt.
    Used for visual feedback in the CLI interface.
    """
    RED = '\033[91m'        # Error, fail, weak
    YELLOW = '\033[93m'     # Warning, moderate
    GREEN = '\033[92m'      # Success, strong
    BLUE = '\033[94m'       # Info messages
    CYAN = '\033[96m'       # Section headers
    MAGENTA = '\033[95m'    # Special highlights
    RESET = '\033[0m'       # Reset to default
    BOLD = '\033[1m'        # Bold text


# ============================================================================
# APPLICATION METADATA
# ============================================================================

APP_NAME = "Password Strength Checker"
APP_VERSION = "0.3.0"
APP_STAGE = "Modular Refactoring"