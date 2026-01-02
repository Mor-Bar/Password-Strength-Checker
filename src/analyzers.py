"""
Password Analysis and Pattern Detection
=======================================
Advanced analysis functions including entropy calculation and
weak pattern detection.

This module provides mathematical analysis and pattern recognition
to identify predictable or weak elements in passwords.
"""

import math                   # For entropy calculations (log2)
import re                     # For pattern matching with regex

from .config import (
    UPPERCASE_CHARS,
    LOWERCASE_CHARS,
    DIGIT_CHARS,
    SPECIAL_CHARS,
    KEYBOARD_PATTERNS,
    PATTERN_PENALTIES,
    ENTROPY_THRESHOLDS,
    Colors
)


# ============================================================================
# ENTROPY CALCULATION
# ============================================================================

def calculate_entropy(password: str) -> float:
    """
    Calculates Shannon entropy of the password.
    
    Entropy measures the unpredictability and randomness of a password.
    Higher entropy values indicate stronger, more random passwords that
    are harder to crack through brute-force or dictionary attacks.
    
    Formula: H = L × log₂(N)
    Where:
        - H = Entropy in bits
        - L = Password length
        - N = Size of character pool (alphabet)
    
    Character Pool Calculation:
        - Lowercase (a-z): +26 characters
        - Uppercase (A-Z): +26 characters
        - Digits (0-9): +10 characters
        - Special chars: +32 characters (approximate)
    
    Args:
        password (str): The password string to analyze
    
    Returns:
        float: Entropy value in bits, rounded to 2 decimal places
    
    Example:
        >>> calculate_entropy("password")
        37.60  # Only lowercase: 8 × log₂(26)
        
        >>> calculate_entropy("Password123!")
        76.32  # Mixed case + digits + special: 12 × log₂(94)
    
    Interpretation:
        - < 28 bits: Very weak (crackable in seconds)
        - 28-35 bits: Weak (crackable in minutes/hours)
        - 36-59 bits: Reasonable (crackable in days/weeks)
        - 60-79 bits: Strong (crackable in months/years)
        - 80+ bits: Very strong (computationally infeasible)
    
    Security Note:
        Entropy alone doesn't account for common patterns or dictionary
        words. A password like "Tr0ub4dor&3" has high entropy but is
        still weaker than a random string of the same length.
    """
    if not password:
        return 0.0
    
    # Determine character pool size based on character types present
    pool_size = 0
    
    # Check for lowercase letters
    if any(c in LOWERCASE_CHARS for c in password):
        pool_size += 26  # a-z
    
    # Check for uppercase letters
    if any(c in UPPERCASE_CHARS for c in password):
        pool_size += 26  # A-Z
    
    # Check for digits
    if any(c in DIGIT_CHARS for c in password):
        pool_size += 10  # 0-9
    
    # Check for special characters
    if any(c in SPECIAL_CHARS for c in password):
        pool_size += 32  # Approximate special char count
    
    # If no recognized characters, return 0
    if pool_size == 0:
        return 0.0
    
    # Calculate entropy: length × log₂(pool_size)
    entropy = len(password) * math.log2(pool_size)
    
    return round(entropy, 2)


def get_entropy_rating(entropy: float) -> tuple[str, str]:
    """
    Converts entropy value to human-readable rating.
    
    Provides a qualitative assessment of the entropy value
    along with appropriate color coding for display.
    
    Args:
        entropy (float): Entropy value in bits
    
    Returns:
        tuple[str, str]: Contains:
            - str: Rating description (e.g., "High", "Moderate")
            - str: ANSI color code for display
    
    Rating Scale:
        - < 28 bits: Very Low (Red)
        - 28-35 bits: Low (Red)
        - 36-59 bits: Moderate (Yellow)
        - 60-79 bits: High (Green)
        - 80+ bits: Very High (Green)
    """
    if entropy < ENTROPY_THRESHOLDS['very_low']:
        return "Very Low", Colors.RED
    elif entropy < ENTROPY_THRESHOLDS['low']:
        return "Low", Colors.RED
    elif entropy < ENTROPY_THRESHOLDS['moderate']:
        return "Moderate", Colors.YELLOW
    elif entropy < ENTROPY_THRESHOLDS['high']:
        return "High", Colors.GREEN
    else:
        return "Very High", Colors.GREEN


# ============================================================================
# PATTERN DETECTION FUNCTIONS
# ============================================================================

def detect_sequential_chars(password: str) -> list[str]:
    """
    Detects sequential character patterns in the password.
    
    Identifies predictable sequences of 3 or more consecutive characters:
    - Alphabetic sequences: "abc", "xyz", "DEF"
    - Numeric sequences: "123", "789", "456"
    
    These patterns are weak because they're easy to guess and commonly
    used in passwords (e.g., "abc123", "password123").
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected sequential patterns (3+ chars)
                  Returns empty list if no patterns found
    
    Example:
        >>> detect_sequential_chars("Password123abc")
        ['123', 'abc']
        
        >>> detect_sequential_chars("MyP@ssw0rd")
        []
    
    Algorithm:
        1. Check each 3-character window in the password
        2. For alphabetic: verify ASCII values are consecutive
        3. For numeric: verify integer values are consecutive
        4. Case-insensitive for alphabetic patterns
    """
    patterns_found = []
    password_lower = password.lower()
    
    # Check for sequential alphabetic patterns (length 3+)
    for i in range(len(password_lower) - 2):
        # Get 3 consecutive characters
        char1, char2, char3 = password_lower[i:i+3]
        
        # Check if all are alphabetic
        if char1.isalpha() and char2.isalpha() and char3.isalpha():
            # Check if they're sequential in ASCII
            if ord(char2) == ord(char1) + 1 and ord(char3) == ord(char2) + 1:
                # Use original case from password
                pattern = password[i:i+3]
                if pattern not in patterns_found:
                    patterns_found.append(pattern)
    
    # Check for sequential numeric patterns (length 3+)
    for i in range(len(password) - 2):
        char1, char2, char3 = password[i:i+3]
        
        # Check if all are digits
        if char1.isdigit() and char2.isdigit() and char3.isdigit():
            # Check if they're sequential
            if int(char2) == int(char1) + 1 and int(char3) == int(char2) + 1:
                pattern = password[i:i+3]
                if pattern not in patterns_found:
                    patterns_found.append(pattern)
    
    return patterns_found


def detect_repeated_chars(password: str) -> list[str]:
    """
    Detects repeated character patterns in the password.
    
    Identifies sequences where the same character appears 3 or more
    times consecutively. Repeated characters indicate low entropy
    and predictability.
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected repeated patterns (3+ chars)
                  Returns empty list if no patterns found
    
    Example:
        >>> detect_repeated_chars("Passsword111")
        ['sss', '111']
        
        >>> detect_repeated_chars("Password")
        []
    
    Implementation:
        Uses regex pattern: (.)\1{2,}
        - (.) captures any single character
        - \1 backreference to captured character
        - {2,} matches 2 or more additional occurrences
        - Total: 3+ consecutive identical characters
    """
    patterns_found = []
    
    # Regex pattern: any character repeated 3+ times
    # (.) captures one char, \1{2,} matches 2+ more of same char
    repeated_pattern = r'(.)\1{2,}'
    matches = re.finditer(repeated_pattern, password)
    
    for match in matches:
        pattern = match.group()
        if pattern not in patterns_found:
            patterns_found.append(pattern)
    
    return patterns_found


def detect_common_years(password: str) -> list[str]:
    """
    Detects common year patterns in the password.
    
    Years are highly predictable and commonly used in passwords:
    - Birth years: 1950-1999
    - Recent years: 2000-2026
    
    These patterns are weak because:
    - Limited range (only ~70 common years)
    - Easy to guess (birth year, current year)
    - Frequently used in password attacks
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected year patterns
                  Returns empty list if no patterns found
    
    Example:
        >>> detect_common_years("Password2024")
        ['2024']
        
        >>> detect_common_years("MyP@ssw0rd")
        []
    
    Detection Range:
        - 1950-1999: Birth years and historical dates
        - 2000-2026: Recent years and current date
    
    Regex Pattern:
        - 19[5-9]\d matches 1950-1999
        - 20[0-2]\d matches 2000-2029
    """
    patterns_found = []
    
    # Regex pattern for 4-digit years
    # 19[5-9]\d: years 1950-1999
    # 20[0-2]\d: years 2000-2029
    year_pattern = r'(19[5-9]\d|20[0-2]\d)'
    matches = re.finditer(year_pattern, password)
    
    for match in matches:
        year = match.group()
        if year not in patterns_found:
            patterns_found.append(year)
    
    return patterns_found


def detect_keyboard_patterns(password: str) -> list[str]:
    """
    Detects common keyboard pattern sequences.
    
    Keyboard patterns are character sequences that follow physical
    keyboard layouts. They're easy to type but highly predictable:
    - QWERTY rows: "qwerty", "asdfgh", "zxcvbn"
    - Number sequences: "12345", "123456"
    - Common weak patterns: "password", "admin"
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected keyboard patterns
                  Returns empty list if no patterns found
    
    Example:
        >>> detect_keyboard_patterns("MyQwerty123")
        ['Qwerty', '123']
        
        >>> detect_keyboard_patterns("X9$mK2pL")
        []
    
    Detection Method:
        1. Convert password to lowercase for matching
        2. Check against predefined KEYBOARD_PATTERNS list
        3. Preserve original case in returned results
    
    Note:
        Case-insensitive matching (qwerty = QWERTY = Qwerty)
        but returns patterns with original case preserved.
    """
    patterns_found = []
    password_lower = password.lower()
    
    # Check against known keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            # Find the substring with original case
            start_idx = password_lower.index(pattern)
            original_pattern = password[start_idx:start_idx + len(pattern)]
            
            if original_pattern not in patterns_found:
                patterns_found.append(original_pattern)
    
    return patterns_found


# ============================================================================
# COMPREHENSIVE PATTERN DETECTION
# ============================================================================

def detect_weak_patterns(password: str) -> dict:
    """
    Comprehensive weak pattern detection orchestrator.
    
    Runs all pattern detection functions and aggregates the results.
    This is the main entry point for pattern analysis.
    
    Detects:
        1. Sequential characters (abc, 123)
        2. Repeated characters (aaa, 111)
        3. Common year patterns (2024, 1990)
        4. Keyboard patterns (qwerty, asdfgh)
    
    Args:
        password (str): The password to analyze
    
    Returns:
        dict: Comprehensive pattern analysis results containing:
            - patterns (dict): Detected patterns by type
                - sequential (list): Sequential patterns found
                - repeated (list): Repeated patterns found
                - common_year (list): Year patterns found
                - keyboard_pattern (list): Keyboard patterns found
            - total_penalty (int): Sum of all penalty points
            - has_patterns (bool): True if any patterns detected
    
    Example:
        >>> detect_weak_patterns("Password123")
        {
            'patterns': {
                'sequential': ['123'],
                'repeated': [],
                'common_year': [],
                'keyboard_pattern': ['password']
            },
            'total_penalty': 25,
            'has_patterns': True
        }
    
    Penalty System:
        - Sequential: -10 points per detection
        - Repeated: -10 points per detection
        - Common year: -5 points per detection
        - Keyboard pattern: -15 points per detection
    
    Note:
        Penalties are applied once per pattern type, not per instance.
        If multiple sequential patterns exist, penalty is still only -10.
    """
    results = {
        'patterns': {
            'sequential': [],
            'repeated': [],
            'common_year': [],
            'keyboard_pattern': []
        },
        'total_penalty': 0,
        'has_patterns': False
    }
    
    # Run all detection functions
    results['patterns']['sequential'] = detect_sequential_chars(password)
    results['patterns']['repeated'] = detect_repeated_chars(password)
    results['patterns']['common_year'] = detect_common_years(password)
    results['patterns']['keyboard_pattern'] = detect_keyboard_patterns(password)
    
    # Calculate total penalty
    # Apply penalty once per pattern type (not per instance)
    for pattern_type, instances in results['patterns'].items():
        if instances:  # If any patterns of this type were found
            results['total_penalty'] += PATTERN_PENALTIES[pattern_type]
            results['has_patterns'] = True
    
    return results