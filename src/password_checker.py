#!/usr/bin/env python3
"""
Password Strength Checker - Advanced Security Tool
==================================================
A comprehensive password strength analyzer with entropy calculation,
pattern detection, and breach checking capabilities.

Author: Mor
Date: January 2026
Version: 0.1.0
"""

import sys

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Minimum password length requirements
MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12

# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for formatted terminal output"""
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ============================================================================
# CORE VALIDATION FUNCTIONS
# ============================================================================

def check_password_length(password: str, min_length: int = MIN_PASSWORD_LENGTH) -> tuple[bool, str]:
    """
    Validates password length against security standards.
    
    This function checks if the password meets minimum length requirements
    and provides recommendations based on current security best practices.
    
    Args:
        password (str): The password string to validate
        min_length (int): Minimum acceptable length (default: 8 characters)
    
    Returns:
        tuple[bool, str]: A tuple containing:
            - bool: True if password meets minimum requirements, False otherwise
            - str: Detailed feedback message with color coding
    
    Security Notes:
        - Passwords < 8 characters are considered weak
        - Passwords 8-11 characters are acceptable but not recommended
        - Passwords >= 12 characters meet modern security standards
    """
    length = len(password)
    
    # Check against minimum requirement
    if length < min_length:
        message = (f"{Colors.RED}[FAIL]{Colors.RESET} "
                  f"Password too short: {length} characters "
                  f"(minimum required: {min_length})")
        return False, message
    
    # Check against recommended length
    elif length < RECOMMENDED_PASSWORD_LENGTH:
        message = (f"{Colors.YELLOW}[WARN]{Colors.RESET} "
                  f"Password length acceptable: {length} characters "
                  f"(recommended: {RECOMMENDED_PASSWORD_LENGTH}+)")
        return True, message
    
    # Meets or exceeds recommendations
    else:
        message = (f"{Colors.GREEN}[PASS]{Colors.RESET} "
                  f"Password length excellent: {length} characters")
        return True, message


# ============================================================================
# USER INTERFACE FUNCTIONS
# ============================================================================

def print_header():
    """
    Displays the application header with version information.
    
    This function prints a formatted header to the terminal, including
    the tool name, version, and basic usage instructions.
    """
    separator = "=" * 60
    print(f"\n{Colors.BOLD}{separator}{Colors.RESET}")
    print(f"{Colors.BOLD}Password Strength Checker{Colors.RESET}")
    print(f"{Colors.BLUE}Version 0.1.0 - Development Stage 1{Colors.RESET}")
    print(f"{separator}")
    print(f"Type 'exit' or press Ctrl+C to quit")
    print(f"{separator}\n")


def print_footer():
    """
    Displays exit message when user terminates the application.
    """
    print(f"\n{Colors.BLUE}[INFO]{Colors.RESET} Application terminated by user")
    print("Thank you for using Password Strength Checker\n")


# ============================================================================
# MAIN APPLICATION LOGIC
# ============================================================================

def main():
    """
    Main application entry point.
    
    Implements the primary application loop, handling user input,
    password validation, and graceful exit on user termination.
    
    Flow:
        1. Display application header
        2. Enter main loop for continuous password checking
        3. Handle user input and validation
        4. Display results with color-coded feedback
        5. Handle exit conditions (KeyboardInterrupt or 'exit' command)
    
    Exit Conditions:
        - User types 'exit' (case-insensitive)
        - User presses Ctrl+C (KeyboardInterrupt)
    """
    # Display application header
    print_header()
    
    # Main application loop
    while True:
        try:
            # Get password input from user
            password = input(f"{Colors.BOLD}Enter password to check: {Colors.RESET}")
            
            # Check for exit command
            if password.lower() == 'exit':
                print_footer()
                sys.exit(0)
            
            # Skip empty input
            if not password:
                print(f"{Colors.YELLOW}[WARN]{Colors.RESET} Empty input - please enter a password\n")
                continue
            
            # Perform password length validation
            passed, message = check_password_length(password)
            
            # Display validation results
            print(f"{message}\n")
            
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            print_footer()
            sys.exit(0)
        
        except Exception as e:
            # Catch any unexpected errors
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Unexpected error: {str(e)}\n")
            continue


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()