"""
Additional Password Checks
=========================
Extended validation including common password detection,
breach checking, and recommendation generation.
"""

import os
import hashlib          # NEW - for SHA-1 hashing
import requests         # NEW - for API calls
from typing import Optional

from .config import (
    COMMON_PASSWORDS_FILE,
    HIBP_API_URL,
    API_TIMEOUT,
    Colors
)


# ============================================================================
# COMMON PASSWORDS CHECK
# ============================================================================

def load_common_passwords() -> set[str]:
    """
    Loads common passwords from file into a set for fast lookup.
    
    Reads the common passwords file and creates a set containing
    all passwords in lowercase for case-insensitive matching.
    
    Returns:
        set[str]: Set of common passwords (lowercase)
                 Returns empty set if file not found
    
    Performance:
        - Set provides O(1) lookup time
        - File is read once and cached in memory
        - Case-insensitive comparison
    
    File Format:
        One password per line, e.g.:
        password
        123456
        qwerty
    """
    try:
        # Check if file exists
        if not os.path.exists(COMMON_PASSWORDS_FILE):
            print(f"{Colors.YELLOW}[WARN]{Colors.RESET} "
                  f"Common passwords file not found: {COMMON_PASSWORDS_FILE}")
            return set()
        
        # Read file and create set
        with open(COMMON_PASSWORDS_FILE, 'r', encoding='utf-8') as f:
            # Strip whitespace and convert to lowercase
            passwords = {line.strip().lower() for line in f if line.strip()}
        
        return passwords
    
    except Exception as e:
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET} "
              f"Error loading common passwords: {str(e)}")
        return set()


# Cache the common passwords set to avoid reading file multiple times
_COMMON_PASSWORDS_CACHE: Optional[set[str]] = None


def check_common_password(password: str) -> tuple[bool, str]:
    """
    Checks if password exists in common passwords list.
    
    Compares the password against a database of commonly used passwords
    that are known to be weak and frequently targeted in attacks.
    
    Args:
        password (str): The password to check
    
    Returns:
        tuple[bool, str]: Contains:
            - bool: True if password is common (bad), False if not found (good)
            - str: Detailed message
    
    Example:
        >>> check_common_password("password123")
        (True, "Password found in common passwords database - HIGH RISK")
        
        >>> check_common_password("MyP@ssw0rd!X9")
        (False, "Password not found in common passwords database")
    
    Security Impact:
        Common passwords are the first to be tried in attacks:
        - Dictionary attacks
        - Credential stuffing
        - Brute force with common lists
        
        If password is common, it should be rejected regardless of
        its length or complexity.
    """
    global _COMMON_PASSWORDS_CACHE
    
    # Load common passwords into cache if not already loaded
    if _COMMON_PASSWORDS_CACHE is None:
        _COMMON_PASSWORDS_CACHE = load_common_passwords()
    
    # Check if password is in the common list (case-insensitive)
    if password.lower() in _COMMON_PASSWORDS_CACHE:
        return True, "Password found in common passwords database - HIGH RISK"
    else:
        return False, "Password not found in common passwords database"


# ============================================================================
# RECOMMENDATIONS ENGINE
# ============================================================================

def generate_recommendations(results: dict) -> list[str]:
    """
    Generates specific recommendations for password improvement.
    
    Analyzes the password analysis results and provides actionable
    recommendations to strengthen the password.
    
    Args:
        results (dict): Analysis results from analyze_password()
    
    Returns:
        list[str]: List of specific recommendations
    
    Example:
        >>> recommendations = generate_recommendations(results)
        >>> for rec in recommendations:
        ...     print(f"- {rec}")
    """
    recommendations = []
    
    # Get password length safely
    password_len = len(results.get('password', ''))
    
    # Check failed validations
    for check in results['checks']:
        if not check['passed']:
            if check['name'] == 'Length':
                recommendations.append(
                    f"Increase password length to at least 12 characters "
                    f"(currently {password_len})"
                )
            elif check['name'] == 'Uppercase':
                recommendations.append("Add uppercase letters (A-Z)")
            elif check['name'] == 'Lowercase':
                recommendations.append("Add lowercase letters (a-z)")
            elif check['name'] == 'Digits':
                recommendations.append("Add numeric digits (0-9)")
            elif check['name'] == 'Special Chars':
                recommendations.append("Add special characters (!@#$%^&*)")
    
    # Check for weak patterns
    if results.get('has_weak_patterns'):
        recommendations.append(
            "Avoid predictable patterns (sequential chars, repetition, common words)"
        )
    
    # Check for common password
    if results.get('is_common'):
        recommendations.append(
            "CRITICAL: Never use common passwords - this one is in the top 10,000 most used"
        )
    
    # Check for breached password
    if results.get('is_pwned'):
        breach_count = results.get('pwned_count', 0)
        recommendations.append(
            f"CRITICAL: Password exposed in {breach_count:,} data breaches - change immediately"
        )
    
    # Check entropy
    if results.get('entropy', 0) < 60:
        recommendations.append(
            "Increase randomness - use a mix of unrelated characters"
        )
    
    # General advice if score is low
    if results.get('final_score', 0) < 60:
        recommendations.append(
            "Consider using a passphrase (4+ random words) or password manager"
        )
    
    return recommendations


# ============================================================================
# HAVE I BEEN PWNED API CHECK
# ============================================================================

def check_pwned_password(password: str) -> tuple[bool, str, int]:
    """
    Checks if password has been exposed in known data breaches.
    
    Uses the Have I Been Pwned (HIBP) API with k-anonymity model:
    1. Computes SHA-1 hash of password
    2. Sends only first 5 characters of hash to API
    3. Receives list of hash suffixes that match the prefix
    4. Checks if full hash exists in the returned list
    
    This approach ensures the password is never transmitted in plaintext
    or full hash form, maintaining privacy.
    
    Args:
        password (str): The password to check
    
    Returns:
        tuple[bool, str, int]: Contains:
            - bool: True if password found in breaches (bad)
            - str: Detailed message about the check
            - int: Number of times seen in breaches (0 if not found)
    
    Example:
        >>> check_pwned_password("password123")
        (True, "Password found in 123,456 data breaches - CRITICAL RISK", 123456)
        
        >>> check_pwned_password("MyP@ssw0rd!X9")
        (False, "Password not found in known data breaches", 0)
    
    API Reference:
        https://haveibeenpwned.com/API/v3#PwnedPasswords
    
    Security Note:
        - Uses k-anonymity to protect password privacy
        - Only first 5 chars of SHA-1 hash are sent
        - API returns ~500 hash suffixes on average
        - Client-side matching ensures full hash never transmitted
    
    Error Handling:
        - Network errors: Returns (False, warning message, 0)
        - Timeout: Returns (False, warning message, 0)
        - API errors: Returns (False, warning message, 0)
    """
    try:
        # Step 1: Compute SHA-1 hash of password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Step 2: Split hash into prefix (5 chars) and suffix
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        # Step 3: Query API with hash prefix
        api_url = f"{HIBP_API_URL}{hash_prefix}"
        
        response = requests.get(
            api_url,
            timeout=API_TIMEOUT,
            headers={'User-Agent': 'Password-Strength-Checker'}
        )
        
        # Check if request was successful
        if response.status_code != 200:
            return False, f"API check unavailable (status: {response.status_code})", 0
        
        # Step 4: Parse response and look for our hash suffix
        # Response format: "SUFFIX:COUNT\r\n" for each hash
        for line in response.text.splitlines():
            if ':' in line:
                returned_suffix, count = line.split(':')
                
                # Check if this hash matches ours
                if returned_suffix == hash_suffix:
                    count = int(count)
                    
                    # Format count with thousands separator
                    count_formatted = f"{count:,}"
                    
                    # Determine severity
                    if count > 100000:
                        severity = "CRITICAL RISK"
                    elif count > 10000:
                        severity = "VERY HIGH RISK"
                    elif count > 1000:
                        severity = "HIGH RISK"
                    else:
                        severity = "MODERATE RISK"
                    
                    message = (f"Password found in {count_formatted} data breaches - "
                             f"{severity}")
                    
                    return True, message, count
        
        # Hash not found in breach database
        return False, "Password not found in known data breaches", 0
    
    except requests.exceptions.Timeout:
        # API timeout
        return False, "Breach check timed out - skipping", 0
    
    except requests.exceptions.RequestException as e:
        # Network or connection error
        return False, f"Breach check unavailable - {type(e).__name__}", 0
    
    except Exception as e:
        # Unexpected error
        return False, f"Breach check error - {type(e).__name__}", 0