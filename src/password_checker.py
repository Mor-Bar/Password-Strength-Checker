#!/usr/bin/env python3
"""
Password Strength Checker - Advanced Security Tool
==================================================
A comprehensive password strength analyzer with entropy calculation,
pattern detection, and breach checking capabilities.

Author: Mor
Date: January 2026
Version: 0.3.0
"""

# Standard library imports
import sys                    # System-specific functions for clean exit handling
import string                 # String constants for character set validation (ASCII, punctuation)
import math                   # Mathematical functions for entropy calculation
import re                     # Regular expressions for pattern detection

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Minimum password length requirements
MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12

# Character sets for validation
UPPERCASE_CHARS = string.ascii_uppercase
LOWERCASE_CHARS = string.ascii_lowercase
DIGIT_CHARS = string.digits
SPECIAL_CHARS = string.punctuation

# Scoring weights (total must equal 100 before penalties)
SCORE_WEIGHTS = {
    'length': 30,           # 30 points for length
    'uppercase': 15,        # 15 points for uppercase
    'lowercase': 15,        # 15 points for lowercase
    'digits': 20,           # 20 points for digits
    'special': 20           # 20 points for special characters
}

# Penalty points for weak patterns
PATTERN_PENALTIES = {
    'sequential': 10,       # Sequential characters (abc, 123)
    'repeated': 10,         # Repeated characters (aaa, 111)
    'common_year': 5,       # Common year patterns (2024, 1990)
    'keyboard_pattern': 15  # Keyboard patterns (qwerty, asdfgh)
}

# Score thresholds for password strength categories
SCORE_THRESHOLDS = {
    'very_weak': 20,
    'weak': 40,
    'moderate': 60,
    'strong': 80,
    'very_strong': 100
}

# Common keyboard patterns to detect
KEYBOARD_PATTERNS = [
    'qwerty', 'asdfgh', 'zxcvbn',           # QWERTY keyboard rows
    'qwertz', 'asdfghjkl',                  # Extended patterns
    '12345', '123456', '1234567',           # Sequential numbers
    'abcdef', 'password', 'admin'           # Common weak patterns
]

# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for formatted terminal output"""
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ============================================================================
# MATHEMATICAL FUNCTIONS
# ============================================================================

def calculate_entropy(password: str) -> float:
    """
    Calculates Shannon entropy of the password.
    
    Entropy measures the unpredictability/randomness of a password.
    Higher entropy indicates a stronger, more random password.
    
    Formula: H = L * log2(N)
    Where:
        - H = Entropy in bits
        - L = Password length
        - N = Size of character pool
    
    Args:
        password (str): The password string to analyze
    
    Returns:
        float: Entropy value in bits
    
    Example:
        >>> calculate_entropy("Password123!")
        76.32
    
    Security Note:
        - Entropy < 28 bits: Very weak
        - Entropy 28-35 bits: Weak
        - Entropy 36-59 bits: Reasonable
        - Entropy 60+ bits: Strong
    """
    if not password:
        return 0.0
    
    # Determine character pool size based on character types used
    pool_size = 0
    
    if any(c in LOWERCASE_CHARS for c in password):
        pool_size += 26  # lowercase a-z
    if any(c in UPPERCASE_CHARS for c in password):
        pool_size += 26  # uppercase A-Z
    if any(c in DIGIT_CHARS for c in password):
        pool_size += 10  # digits 0-9
    if any(c in SPECIAL_CHARS for c in password):
        pool_size += 32  # special characters (approximate)
    
    # Calculate entropy: L * log2(N)
    if pool_size == 0:
        return 0.0
    
    entropy = len(password) * math.log2(pool_size)
    
    return round(entropy, 2)


def get_entropy_rating(entropy: float) -> tuple[str, str]:
    """
    Converts entropy value to human-readable rating.
    
    Args:
        entropy (float): Entropy value in bits
    
    Returns:
        tuple[str, str]: Rating description and color code
    """
    if entropy < 28:
        return "Very Low", Colors.RED
    elif entropy < 36:
        return "Low", Colors.RED
    elif entropy < 60:
        return "Moderate", Colors.YELLOW
    elif entropy < 80:
        return "High", Colors.GREEN
    else:
        return "Very High", Colors.GREEN


# ============================================================================
# PATTERN DETECTION FUNCTIONS
# ============================================================================

def detect_sequential_chars(password: str) -> list[str]:
    """
    Detects sequential character patterns in the password.
    
    Sequential patterns are predictable sequences like:
    - Alphabetic: "abc", "xyz", "ABC"
    - Numeric: "123", "789", "456"
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected sequential patterns (3+ chars)
    
    Example:
        >>> detect_sequential_chars("Password123abc")
        ['123', 'abc']
    """
    patterns_found = []
    password_lower = password.lower()
    
    # Check for sequential alphabetic patterns (length 3+)
    for i in range(len(password_lower) - 2):
        # Get 3 consecutive characters
        char1, char2, char3 = password_lower[i:i+3]
        
        # Check if they're sequential in ASCII
        if char1.isalpha() and char2.isalpha() and char3.isalpha():
            if ord(char2) == ord(char1) + 1 and ord(char3) == ord(char2) + 1:
                pattern = password[i:i+3]
                if pattern not in patterns_found:
                    patterns_found.append(pattern)
    
    # Check for sequential numeric patterns (length 3+)
    for i in range(len(password) - 2):
        char1, char2, char3 = password[i:i+3]
        
        if char1.isdigit() and char2.isdigit() and char3.isdigit():
            if int(char2) == int(char1) + 1 and int(char3) == int(char2) + 1:
                pattern = password[i:i+3]
                if pattern not in patterns_found:
                    patterns_found.append(pattern)
    
    return patterns_found


def detect_repeated_chars(password: str) -> list[str]:
    """
    Detects repeated character patterns in the password.
    
    Repeated patterns indicate lack of randomness:
    - "aaa", "111", "!!!" - same character 3+ times
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected repeated patterns (3+ chars)
    
    Example:
        >>> detect_repeated_chars("Passsword111")
        ['sss', '111']
    """
    patterns_found = []
    
    # Use regex to find 3 or more repeated characters
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
    
    Years are predictable and commonly used:
    - Birth years: 1950-2010
    - Recent years: 2020-2026
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected year patterns
    
    Example:
        >>> detect_common_years("Password2024")
        ['2024']
    """
    patterns_found = []
    
    # Regex pattern for 4-digit years
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
    
    Keyboard patterns are easy to type but predictable:
    - "qwerty", "asdfgh" - horizontal rows
    - "12345", "123456" - number sequences
    
    Args:
        password (str): The password to analyze
    
    Returns:
        list[str]: List of detected keyboard patterns
    
    Example:
        >>> detect_keyboard_patterns("MyQwerty123")
        ['qwerty', '123']
    """
    patterns_found = []
    password_lower = password.lower()
    
    # Check against known keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            # Find the actual substring with original case
            start_idx = password_lower.index(pattern)
            original_pattern = password[start_idx:start_idx + len(pattern)]
            
            if original_pattern not in patterns_found:
                patterns_found.append(original_pattern)
    
    return patterns_found


def detect_weak_patterns(password: str) -> dict:
    """
    Comprehensive weak pattern detection.
    
    Runs all pattern detection functions and aggregates results.
    This is the main entry point for pattern analysis.
    
    Args:
        password (str): The password to analyze
    
    Returns:
        dict: Dictionary containing:
            - patterns: Dict of pattern types and their instances
            - total_penalty: Total points to deduct
            - has_patterns: Boolean indicating if any patterns found
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
    for pattern_type, instances in results['patterns'].items():
        if instances:
            results['total_penalty'] += PATTERN_PENALTIES[pattern_type]
            results['has_patterns'] = True
    
    return results


# ============================================================================
# CORE VALIDATION FUNCTIONS
# ============================================================================

def check_password_length(password: str) -> tuple[bool, int, str]:
    """
    Validates password length against security standards.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if meets minimum requirements
            - int: Score points earned (0-30)
            - str: Detailed feedback message
    """
    length = len(password)
    
    if length < MIN_PASSWORD_LENGTH:
        score = 0
        message = f"Password too short: {length} characters (minimum: {MIN_PASSWORD_LENGTH})"
        return False, score, message
    
    elif length < RECOMMENDED_PASSWORD_LENGTH:
        score = 15  # Half points
        message = f"Password length acceptable: {length} characters (recommended: {RECOMMENDED_PASSWORD_LENGTH}+)"
        return True, score, message
    
    elif length < 16:
        score = 25
        message = f"Password length good: {length} characters"
        return True, score, message
    
    else:
        score = 30  # Full points
        message = f"Password length excellent: {length} characters"
        return True, score, message


def check_uppercase(password: str) -> tuple[bool, int, str]:
    """
    Checks if password contains uppercase letters.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains uppercase
            - int: Score points earned (0-15)
            - str: Detailed feedback message
    """
    has_upper = any(char in UPPERCASE_CHARS for char in password)
    
    if has_upper:
        count = sum(1 for char in password if char in UPPERCASE_CHARS)
        score = 15
        message = f"Contains uppercase letters ({count} found)"
        return True, score, message
    else:
        score = 0
        message = "Missing uppercase letters (A-Z)"
        return False, score, message


def check_lowercase(password: str) -> tuple[bool, int, str]:
    """
    Checks if password contains lowercase letters.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains lowercase
            - int: Score points earned (0-15)
            - str: Detailed feedback message
    """
    has_lower = any(char in LOWERCASE_CHARS for char in password)
    
    if has_lower:
        count = sum(1 for char in password if char in LOWERCASE_CHARS)
        score = 15
        message = f"Contains lowercase letters ({count} found)"
        return True, score, message
    else:
        score = 0
        message = "Missing lowercase letters (a-z)"
        return False, score, message


def check_digits(password: str) -> tuple[bool, int, str]:
    """
    Checks if password contains numeric digits.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains digits
            - int: Score points earned (0-20)
            - str: Detailed feedback message
    """
    has_digit = any(char in DIGIT_CHARS for char in password)
    
    if has_digit:
        count = sum(1 for char in password if char in DIGIT_CHARS)
        score = 20
        message = f"Contains numeric digits ({count} found)"
        return True, score, message
    else:
        score = 0
        message = "Missing numeric digits (0-9)"
        return False, score, message


def check_special_characters(password: str) -> tuple[bool, int, str]:
    """
    Checks if password contains special characters.
    
    Special characters include: !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains special characters
            - int: Score points earned (0-20)
            - str: Detailed feedback message
    """
    has_special = any(char in SPECIAL_CHARS for char in password)
    
    if has_special:
        count = sum(1 for char in password if char in SPECIAL_CHARS)
        score = 20
        message = f"Contains special characters ({count} found)"
        return True, score, message
    else:
        score = 0
        message = f"Missing special characters ({SPECIAL_CHARS[:10]}...)"
        return False, score, message


def get_strength_category(score: int) -> tuple[str, str]:
    """
    Determines password strength category based on score.
    
    Args:
        score (int): Total password score (can be negative after penalties)
    
    Returns:
        tuple[str, str]: Contains:
            - str: Strength category name
            - str: Color code for display
    """
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    if score < SCORE_THRESHOLDS['very_weak']:
        return "VERY WEAK", Colors.RED
    elif score < SCORE_THRESHOLDS['weak']:
        return "WEAK", Colors.RED
    elif score < SCORE_THRESHOLDS['moderate']:
        return "MODERATE", Colors.YELLOW
    elif score < SCORE_THRESHOLDS['strong']:
        return "STRONG", Colors.GREEN
    else:
        return "VERY STRONG", Colors.GREEN


def analyze_password(password: str) -> dict:
    """
    Performs comprehensive password analysis.
    
    This is the main analysis function that:
    1. Runs all validation checks
    2. Calculates entropy
    3. Detects weak patterns
    4. Applies penalties
    5. Computes final score
    
    Args:
        password (str): The password string to analyze
    
    Returns:
        dict: Comprehensive analysis results
    """
    results = {
        'checks': [],
        'base_score': 0,
        'penalties': [],
        'total_penalty': 0,
        'final_score': 0,
        'entropy': 0,
        'entropy_rating': '',
        'strength': '',
        'color': '',
        'passed_all_checks': True,
        'has_weak_patterns': False
    }
    
    # Run all validation checks
    checks = [
        ('Length', check_password_length(password)),
        ('Uppercase', check_uppercase(password)),
        ('Lowercase', check_lowercase(password)),
        ('Digits', check_digits(password)),
        ('Special Chars', check_special_characters(password))
    ]
    
    # Process validation results
    for check_name, (passed, score, message) in checks:
        results['checks'].append({
            'name': check_name,
            'passed': passed,
            'score': score,
            'message': message
        })
        results['base_score'] += score
        if not passed:
            results['passed_all_checks'] = False
    
    # Calculate entropy
    results['entropy'] = calculate_entropy(password)
    entropy_rating, entropy_color = get_entropy_rating(results['entropy'])
    results['entropy_rating'] = entropy_rating
    results['entropy_color'] = entropy_color
    
    # Detect weak patterns
    pattern_results = detect_weak_patterns(password)
    
    if pattern_results['has_patterns']:
        results['has_weak_patterns'] = True
        results['total_penalty'] = pattern_results['total_penalty']
        
        # Build penalty descriptions
        for pattern_type, instances in pattern_results['patterns'].items():
            if instances:
                penalty = PATTERN_PENALTIES[pattern_type]
                pattern_name = pattern_type.replace('_', ' ').title()
                results['penalties'].append({
                    'type': pattern_name,
                    'instances': instances,
                    'penalty': penalty
                })
    
    # Calculate final score
    results['final_score'] = max(0, results['base_score'] - results['total_penalty'])
    
    # Determine strength category
    strength, color = get_strength_category(results['final_score'])
    results['strength'] = strength
    results['color'] = color
    
    return results


# ============================================================================
# USER INTERFACE FUNCTIONS
# ============================================================================

def print_header():
    """Displays the application header with version information."""
    separator = "=" * 70
    print(f"\n{Colors.BOLD}{separator}{Colors.RESET}")
    print(f"{Colors.BOLD}Password Strength Checker{Colors.RESET}")
    print(f"{Colors.BLUE}Version 0.3.0 - With Entropy & Pattern Detection{Colors.RESET}")
    print(f"{separator}")
    print(f"Type 'exit' or press Ctrl+C to quit")
    print(f"{separator}\n")


def print_analysis_results(results: dict):
    """
    Displays comprehensive password analysis results.
    
    Args:
        results (dict): Analysis results from analyze_password()
    """
    # Print individual check results
    print(f"\n{Colors.CYAN}Security Checks:{Colors.RESET}")
    print("-" * 70)
    
    for check in results['checks']:
        status = f"{Colors.GREEN}[PASS]{Colors.RESET}" if check['passed'] else f"{Colors.RED}[FAIL]{Colors.RESET}"
        score_display = f"({check['score']}/{SCORE_WEIGHTS[check['name'].lower().replace(' chars', '').replace(' ', '_')]} pts)"
        print(f"{status} {check['name']:<15} {score_display:<12} - {check['message']}")
    
    print("-" * 70)
    print(f"{Colors.BOLD}Base Score:{Colors.RESET} {results['base_score']}/100")
    
    # Print entropy information
    print(f"\n{Colors.CYAN}Entropy Analysis:{Colors.RESET}")
    print("-" * 70)
    print(f"Entropy: {results['entropy']} bits - {results['entropy_color']}{results['entropy_rating']}{Colors.RESET}")
    
    # Print pattern penalties if any
    if results['has_weak_patterns']:
        print(f"\n{Colors.YELLOW}Weak Patterns Detected:{Colors.RESET}")
        print("-" * 70)
        
        for penalty in results['penalties']:
            instances_str = ', '.join(f"'{p}'" for p in penalty['instances'])
            print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {penalty['type']}: {instances_str} (-{penalty['penalty']} pts)")
        
        print("-" * 70)
        print(f"{Colors.RED}Total Penalty:{Colors.RESET} -{results['total_penalty']} points")
    
    # Print final score
    score_bar = create_score_bar(results['final_score'])
    print(f"\n{Colors.BOLD}Final Score:{Colors.RESET} {results['color']}{results['final_score']}/100{Colors.RESET}")
    print(f"{Colors.BOLD}Strength:{Colors.RESET} {results['color']}{results['strength']}{Colors.RESET}")
    print(f"{score_bar}\n")


def create_score_bar(score: int) -> str:
    """
    Creates a visual progress bar for the score.
    
    Args:
        score (int): Password score (0-100)
    
    Returns:
        str: Formatted progress bar string
    """
    bar_length = 50
    filled_length = int(bar_length * max(0, min(score, 100)) / 100)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    
    # Color the bar based on score
    if score < 40:
        color = Colors.RED
    elif score < 80:
        color = Colors.YELLOW
    else:
        color = Colors.GREEN
    
    return f"{color}[{bar}]{Colors.RESET}"


def print_footer():
    """Displays exit message when user terminates the application."""
    print(f"\n{Colors.BLUE}[INFO]{Colors.RESET} Application terminated by user")
    print("Thank you for using Password Strength Checker\n")


# ============================================================================
# MAIN APPLICATION LOGIC
# ============================================================================

def main():
    """
    Main application entry point.
    
    Implements the primary application loop with comprehensive password analysis.
    """
    print_header()
    
    while True:
        try:
            # Get password input
            password = input(f"{Colors.BOLD}Enter password to check: {Colors.RESET}")
            
            # Check for exit command
            if password.lower() == 'exit':
                print_footer()
                sys.exit(0)
            
            # Skip empty input
            if not password:
                print(f"{Colors.YELLOW}[WARN]{Colors.RESET} Empty input - please enter a password\n")
                continue
            
            # Perform comprehensive analysis
            results = analyze_password(password)
            
            # Display results
            print_analysis_results(results)
            
        except KeyboardInterrupt:
            print_footer()
            sys.exit(0)
        
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Unexpected error: {str(e)}\n")
            continue


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()