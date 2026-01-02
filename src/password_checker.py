#!/usr/bin/env python3
"""
Password Strength Checker - Main Application
============================================
Main entry point and orchestrator for the password strength analysis tool.

This module coordinates between all other modules (validators, analyzers,
display) to provide comprehensive password security assessment.

Architecture:
    - config.py: Constants and configuration
    - validators.py: Character validation functions
    - analyzers.py: Entropy and pattern detection
    - display.py: User interface and output formatting
    - password_checker.py: Main orchestrator (this file)

Author: Mor
Date: January 2026
Version: 0.3.0
"""

import sys

# Import from our modules
from .config import APP_NAME
from .validators import (
    check_password_length,
    check_uppercase,
    check_lowercase,
    check_digits,
    check_special_characters,
    get_strength_category
)
from .analyzers import (
    calculate_entropy,
    get_entropy_rating,
    detect_weak_patterns
)
from .display import (
    print_header,
    print_footer,
    print_analysis_results,
    get_password_input,
    print_warning,
    print_error
)


# ============================================================================
# MAIN ANALYSIS FUNCTION
# ============================================================================

def analyze_password(password: str) -> dict:
    """
    Performs comprehensive password analysis.
    
    This is the main orchestrator function that coordinates all analysis
    steps and combines their results into a complete security assessment.
    
    Analysis Pipeline:
        1. Run all character validation checks
        2. Calculate base score from validations
        3. Calculate password entropy
        4. Detect weak patterns
        5. Apply penalties for weak patterns
        6. Calculate final score
        7. Determine strength category
    
    Args:
        password (str): The password string to analyze
    
    Returns:
        dict: Comprehensive analysis results containing:
            - checks (list): Individual validation results
            - base_score (int): Score before penalties
            - penalties (list): Detected pattern penalties
            - total_penalty (int): Sum of all penalties
            - final_score (int): Score after penalties
            - entropy (float): Shannon entropy in bits
            - entropy_rating (str): Human-readable entropy rating
            - entropy_color (str): Color code for entropy
            - strength (str): Overall strength category
            - color (str): Color code for strength
            - passed_all_checks (bool): True if all validations passed
            - has_weak_patterns (bool): True if patterns detected
    
    Example:
        >>> results = analyze_password("MyP@ssw0rd!X9")
        >>> print(results['final_score'])
        95
        >>> print(results['strength'])
        'VERY STRONG'
    """
    # Initialize results dictionary
    results = {
        'checks': [],
        'base_score': 0,
        'penalties': [],
        'total_penalty': 0,
        'final_score': 0,
        'entropy': 0,
        'entropy_rating': '',
        'entropy_color': '',
        'strength': '',
        'color': '',
        'passed_all_checks': True,
        'has_weak_patterns': False
    }
    
    # ========================================================================
    # STEP 1: Run all validation checks
    # ========================================================================
    
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
        
        # Track if any check failed
        if not passed:
            results['passed_all_checks'] = False
    
    # ========================================================================
    # STEP 2: Calculate entropy
    # ========================================================================
    
    results['entropy'] = calculate_entropy(password)
    entropy_rating, entropy_color = get_entropy_rating(results['entropy'])
    results['entropy_rating'] = entropy_rating
    results['entropy_color'] = entropy_color
    
    # ========================================================================
    # STEP 3: Detect weak patterns
    # ========================================================================
    
    pattern_results = detect_weak_patterns(password)
    
    if pattern_results['has_patterns']:
        results['has_weak_patterns'] = True
        results['total_penalty'] = pattern_results['total_penalty']
        
        # Build penalty descriptions for display
        for pattern_type, instances in pattern_results['patterns'].items():
            if instances:
                # Get penalty amount from config
                from .config import PATTERN_PENALTIES
                penalty = PATTERN_PENALTIES[pattern_type]
                
                # Format pattern type name
                pattern_name = pattern_type.replace('_', ' ').title()
                
                results['penalties'].append({
                    'type': pattern_name,
                    'instances': instances,
                    'penalty': penalty
                })
    
    # ========================================================================
    # STEP 4: Calculate final score with penalties
    # ========================================================================
    
    # Final score = base score - penalties (minimum 0)
    results['final_score'] = max(0, results['base_score'] - results['total_penalty'])
    
    # ========================================================================
    # STEP 5: Determine strength category
    # ========================================================================
    
    strength, color = get_strength_category(results['final_score'])
    results['strength'] = strength
    results['color'] = color
    
    return results


# ============================================================================
# MAIN APPLICATION LOGIC
# ============================================================================

def main():
    """
    Main application entry point.
    
    Implements the primary application loop with user interaction:
        1. Display application header
        2. Enter main loop for continuous password checking
        3. Get password input from user
        4. Validate and analyze password
        5. Display comprehensive results
        6. Handle exit conditions gracefully
    
    Exit Conditions:
        - User types 'exit' (case-insensitive)
        - User presses Ctrl+C (KeyboardInterrupt)
    
    Error Handling:
        - Empty input: Warning message, continue loop
        - Unexpected errors: Error message, continue loop
        - Keyboard interrupt: Clean exit with footer
    """
    # Display application header
    print_header()
    
    # Main application loop
    while True:
        try:
            # Get password input from user
            password = get_password_input()
            
            # Check for exit command
            if password.lower() == 'exit':
                print_footer()
                sys.exit(0)
            
            # Validate input is not empty
            if not password:
                print_warning("Empty input - please enter a password")
                continue
            
            # Perform comprehensive password analysis
            results = analyze_password(password)
            
            # Display results to user
            print_analysis_results(results)
            
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            print_footer()
            sys.exit(0)
        
        except Exception as e:
            # Catch any unexpected errors
            print_error(f"Unexpected error: {str(e)}")
            continue


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()