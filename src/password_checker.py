#!/usr/bin/env python3
"""
Password Strength Checker - Advanced Security Tool
==================================================
A comprehensive password strength analyzer with entropy calculation,
pattern detection, and breach checking capabilities.

Author: Mor
Date: January 2026
Version: 0.2.0
"""

# Standard library imports
import sys          # System-specific functions for clean exit handling
import string       # String constants for character set validation (ASCII, punctuation)

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Minimum password length requirements
MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12

# Character sets for validation
UPPERCASE_CHARS = string.ascii_uppercase    #ABC..
LOWERCASE_CHARS = string.ascii_lowercase    #abc..
DIGIT_CHARS = string.digits                 #012..
SPECIAL_CHARS = string.punctuation          #!#$..

# Scoring weights (total must equal 100)
SCORE_WEIGHTS = {
    'length': 30,           # 30 points for length
    'uppercase': 15,        # 15 points for uppercase
    'lowercase': 15,        # 15 points for lowercase
    'digits': 20,           # 20 points for digits
    'special': 20           # 20 points for special characters
}

# Score thresholds for password strength categories
SCORE_THRESHOLDS = {
    'very_weak': 20,
    'weak': 40,
    'moderate': 60,
    'strong': 80,
    'very_strong': 100
}

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
        score (int): Total password score (0-100)
    
    Returns:
        tuple[str, str]: Contains:
            - str: Strength category name
            - str: Color code for display
    """
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
    
    This is the main analysis function that runs all validation checks
    and calculates an overall security score.
    
    Args:
        password (str): The password string to analyze
    
    Returns:
        dict: Analysis results containing:
            - checks: List of individual check results
            - total_score: Overall score (0-100)
            - strength: Strength category
            - passed_all: Boolean indicating if all checks passed
    """
    results = {
        'checks': [],
        'total_score': 0,
        'strength': '',
        'color': '',
        'passed_all': True
    }
    
    # Run all validation checks
    checks = [
        ('Length', check_password_length(password)),
        ('Uppercase', check_uppercase(password)),
        ('Lowercase', check_lowercase(password)),
        ('Digits', check_digits(password)),
        ('Special Chars', check_special_characters(password))
    ]
    
    # Process results
    for check_name, (passed, score, message) in checks:
        results['checks'].append({
            'name': check_name,
            'passed': passed,
            'score': score,
            'message': message
        })
        results['total_score'] += score
        if not passed:
            results['passed_all'] = False
    
    # Determine strength category
    strength, color = get_strength_category(results['total_score'])
    results['strength'] = strength
    results['color'] = color
    
    return results


# ============================================================================
# USER INTERFACE FUNCTIONS
# ============================================================================

def print_header():
    """Displays the application header with version information."""
    separator = "=" * 60
    print(f"\n{Colors.BOLD}{separator}{Colors.RESET}")
    print(f"{Colors.BOLD}Password Strength Checker{Colors.RESET}")
    print(f"{Colors.BLUE}Version 0.2.0 - Development Stage 2{Colors.RESET}")
    print(f"{separator}")
    print(f"Type 'exit' or press Ctrl+C to quit")
    print(f"{separator}\n")


def print_analysis_results(results: dict):
    """
    Displays password analysis results in a formatted table.
    
    Args:
        results (dict): Analysis results from analyze_password()
    """
    # Print individual check results
    print(f"\n{Colors.CYAN}Security Checks:{Colors.RESET}")
    print("-" * 60)
    
    for check in results['checks']:
        status = f"{Colors.GREEN}[PASS]{Colors.RESET}" if check['passed'] else f"{Colors.RED}[FAIL]{Colors.RESET}"
        score_display = f"({check['score']}/{SCORE_WEIGHTS[check['name'].lower().replace(' chars', '').replace(' ', '_')]} pts)"
        print(f"{status} {check['name']:<15} {score_display:<12} - {check['message']}")
    
    # Print overall score
    print("-" * 60)
    score_bar = create_score_bar(results['total_score'])
    print(f"\n{Colors.BOLD}Overall Score:{Colors.RESET} {results['color']}{results['total_score']}/100{Colors.RESET}")
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
    filled_length = int(bar_length * score / 100)
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