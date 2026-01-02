"""
Password Validation Functions
=============================
Contains all validation logic for checking password characteristics.
Each function validates a specific password requirement and returns
a standardized result tuple.

All validators follow the pattern:
    - Input: password string (+ optional parameters)
    - Output: (passed: bool, score: int, message: str)
"""

from .config import (
    MIN_PASSWORD_LENGTH,
    RECOMMENDED_PASSWORD_LENGTH,
    UPPERCASE_CHARS,
    LOWERCASE_CHARS,
    DIGIT_CHARS,
    SPECIAL_CHARS,
    SCORE_THRESHOLDS,
    Colors
)


# ============================================================================
# CHARACTER TYPE VALIDATORS
# ============================================================================

def check_password_length(password: str) -> tuple[bool, int, str]:
    """
    Validates password length against security standards.
    
    Scoring:
        - < 8 chars: 0 points (fail)
        - 8-11 chars: 15 points (half score)
        - 12-15 chars: 25 points (good)
        - 16+ chars: 30 points (excellent)
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if meets minimum requirements (>= 8 chars)
            - int: Score points earned (0-30)
            - str: Detailed feedback message
    
    Security Note:
        NIST recommends minimum 8 characters, but 12+ is considered
        best practice for strong passwords.
    """
    length = len(password)
    
    # Fail: Below minimum requirement
    if length < MIN_PASSWORD_LENGTH:
        score = 0
        message = (f"Password too short: {length} characters "
                  f"(minimum: {MIN_PASSWORD_LENGTH})")
        return False, score, message
    
    # Pass with warning: Meets minimum but below recommended
    elif length < RECOMMENDED_PASSWORD_LENGTH:
        score = 15  # Half points
        message = (f"Password length acceptable: {length} characters "
                  f"(recommended: {RECOMMENDED_PASSWORD_LENGTH}+)")
        return True, score, message
    
    # Pass: Good length
    elif length < 16:
        score = 25
        message = f"Password length good: {length} characters"
        return True, score, message
    
    # Pass: Excellent length
    else:
        score = 30  # Full points
        message = f"Password length excellent: {length} characters"
        return True, score, message


def check_uppercase(password: str) -> tuple[bool, int, str]:
    """
    Checks if password contains uppercase letters.
    
    Validates presence of at least one uppercase letter (A-Z).
    Also counts and reports the total number found.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains at least one uppercase letter
            - int: Score points earned (0 or 15)
            - str: Detailed feedback message with count
    
    Example:
        >>> check_uppercase("Password123")
        (True, 15, "Contains uppercase letters (1 found)")
    """
    has_upper = any(char in UPPERCASE_CHARS for char in password)
    
    if has_upper:
        # Count how many uppercase letters
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
    
    Validates presence of at least one lowercase letter (a-z).
    Also counts and reports the total number found.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains at least one lowercase letter
            - int: Score points earned (0 or 15)
            - str: Detailed feedback message with count
    
    Example:
        >>> check_lowercase("PASSWORD123")
        (False, 0, "Missing lowercase letters (a-z)")
    """
    has_lower = any(char in LOWERCASE_CHARS for char in password)
    
    if has_lower:
        # Count how many lowercase letters
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
    
    Validates presence of at least one digit (0-9).
    Also counts and reports the total number found.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains at least one digit
            - int: Score points earned (0 or 20)
            - str: Detailed feedback message with count
    
    Example:
        >>> check_digits("Password")
        (False, 0, "Missing numeric digits (0-9)")
    """
    has_digit = any(char in DIGIT_CHARS for char in password)
    
    if has_digit:
        # Count how many digits
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
    
    Validates presence of at least one special character from the set:
    !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    
    Special characters significantly increase password strength by
    expanding the character space and making brute-force attacks harder.
    
    Args:
        password (str): The password string to validate
    
    Returns:
        tuple[bool, int, str]: Contains:
            - bool: True if contains at least one special character
            - int: Score points earned (0 or 20)
            - str: Detailed feedback message with count
    
    Example:
        >>> check_special_characters("Password123!")
        (True, 20, "Contains special characters (1 found)")
    """
    has_special = any(char in SPECIAL_CHARS for char in password)
    
    if has_special:
        # Count how many special characters
        count = sum(1 for char in password if char in SPECIAL_CHARS)
        score = 20
        message = f"Contains special characters ({count} found)"
        return True, score, message
    else:
        score = 0
        # Show first 10 special chars as examples
        message = f"Missing special characters ({SPECIAL_CHARS[:10]}...)"
        return False, score, message


# ============================================================================
# STRENGTH CLASSIFICATION
# ============================================================================

def get_strength_category(score: int) -> tuple[str, str]:
    """
    Determines password strength category based on final score.
    
    Classifies passwords into strength categories using predefined
    thresholds. Also returns the appropriate color code for display.
    
    Score Ranges:
        - 0-19: Very Weak (Red)
        - 20-39: Weak (Red)
        - 40-59: Moderate (Yellow)
        - 60-79: Strong (Green)
        - 80-100: Very Strong (Green)
    
    Args:
        score (int): Total password score (can be negative after penalties,
                    will be normalized to 0 minimum)
    
    Returns:
        tuple[str, str]: Contains:
            - str: Strength category name (e.g., "STRONG")
            - str: ANSI color code for display
    
    Example:
        >>> get_strength_category(75)
        ("STRONG", '\033[92m')
    
    Note:
        Negative scores (from heavy penalties) are normalized to 0
        to prevent misleading categories.
    """
    # Ensure score doesn't go below 0
    normalized_score = max(0, score)
    
    # Classify based on thresholds
    if normalized_score < SCORE_THRESHOLDS['very_weak']:
        return "VERY WEAK", Colors.RED
    
    elif normalized_score < SCORE_THRESHOLDS['weak']:
        return "WEAK", Colors.RED
    
    elif normalized_score < SCORE_THRESHOLDS['moderate']:
        return "MODERATE", Colors.YELLOW
    
    elif normalized_score < SCORE_THRESHOLDS['strong']:
        return "STRONG", Colors.GREEN
    
    else:
        return "VERY STRONG", Colors.GREEN