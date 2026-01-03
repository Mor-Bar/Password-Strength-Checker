"""
Display and User Interface Functions
====================================
Handles all terminal output, formatting, and visual presentation.
Provides colored output, progress bars, tables, and user feedback.

This module is responsible for the presentation layer only,
keeping UI logic separate from business logic.
"""

from .config import (
    Colors,
    SCORE_WEIGHTS,
    APP_NAME,
    APP_VERSION,
    APP_STAGE
)


# ============================================================================
# HEADER AND FOOTER FUNCTIONS
# ============================================================================

def print_header():
    """
    Displays the application header with version information.
    
    Shows:
        - Application name
        - Version and development stage
        - Usage instructions
        - Visual separator
    """
    separator = "=" * 70
    print(f"\n{Colors.BOLD}{separator}{Colors.RESET}")
    print(f"{Colors.BOLD}{APP_NAME}{Colors.RESET}")
    print(f"{Colors.BLUE}Version {APP_VERSION} - {APP_STAGE}{Colors.RESET}")
    print(f"{separator}")
    print(f"Type 'exit' or press Ctrl+C to quit")
    print(f"{separator}\n")


def print_footer():
    """
    Displays exit message when user terminates the application.
    
    Provides a clean exit message with professional formatting.
    """
    print(f"\n{Colors.BLUE}[INFO]{Colors.RESET} Application terminated by user")
    print(f"Thank you for using {APP_NAME}\n")


# ============================================================================
# VISUAL COMPONENTS
# ============================================================================

def create_score_bar(score: int) -> str:
    """
    Creates a visual progress bar for the password score.
    
    Generates a colored ASCII progress bar that visually represents
    the password strength score. The bar color changes based on the
    score value (red for weak, yellow for moderate, green for strong).
    
    Args:
        score (int): Password score (0-100)
    
    Returns:
        str: Formatted progress bar with ANSI colors
    
    Example:
        >>> create_score_bar(75)
        '[████████████████████████████████░░░░░░░░░░░░░░░░░░]'
    """
    bar_length = 50
    
    # Ensure score is within valid range
    normalized_score = max(0, min(score, 100))
    
    # Calculate filled portion
    filled_length = int(bar_length * normalized_score / 100)
    
    # Build the bar
    filled_bar = '█' * filled_length
    empty_bar = '░' * (bar_length - filled_length)
    bar = filled_bar + empty_bar
    
    # Determine color based on score
    if score < 40:
        color = Colors.RED
    elif score < 80:
        color = Colors.YELLOW
    else:
        color = Colors.GREEN
    
    return f"{color}[{bar}]{Colors.RESET}"


def create_separator(length: int = 70) -> str:
    """
    Creates a visual separator line.
    
    Args:
        length (int): Length of the separator line
    
    Returns:
        str: Separator string
    """
    return "-" * length


# ============================================================================
# ANALYSIS RESULTS DISPLAY
# ============================================================================

def print_security_checks(checks: list):
    """
    Displays individual security check results in a formatted table.
    
    Args:
        checks (list): List of check result dictionaries containing:
            - name (str): Check name
            - passed (bool): Whether check passed
            - score (int): Points earned
            - message (str): Detailed message
    """
    print(f"\n{Colors.CYAN}Security Checks:{Colors.RESET}")
    print(create_separator())
    
    for check in checks:
        # Format status indicator
        if check['passed']:
            status = f"{Colors.GREEN}[PASS]{Colors.RESET}"
        else:
            status = f"{Colors.RED}[FAIL]{Colors.RESET}"
        
        # Get max possible score for this check
        check_key = check['name'].lower().replace(' chars', '').replace(' ', '_')
        max_score = SCORE_WEIGHTS.get(check_key, 0)
        
        # Format score display
        score_display = f"({check['score']}/{max_score} pts)"
        
        # Print formatted line
        print(f"{status} {check['name']:<15} {score_display:<12} - {check['message']}")
    
    print(create_separator())


def print_base_score(base_score: int):
    """
    Displays the base score before penalties.
    
    Args:
        base_score (int): Score from validation checks only
    """
    print(f"{Colors.BOLD}Base Score:{Colors.RESET} {base_score}/100")


def print_entropy_analysis(entropy: float, entropy_rating: str, entropy_color: str):
    """
    Displays entropy analysis results.
    
    Entropy measures the randomness/unpredictability of the password.
    Higher entropy indicates a stronger password.
    
    Args:
        entropy (float): Entropy value in bits
        entropy_rating (str): Human-readable rating (e.g., "High")
        entropy_color (str): ANSI color code for the rating
    """
    print(f"\n{Colors.CYAN}Entropy Analysis:{Colors.RESET}")
    print(create_separator())
    print(f"Entropy: {entropy} bits - {entropy_color}{entropy_rating}{Colors.RESET}")


def print_weak_patterns(penalties: list, total_penalty: int):
    """
    Displays detected weak patterns and associated penalties.
    
    Args:
        penalties (list): List of penalty dictionaries containing:
            - type (str): Pattern type name
            - instances (list): List of detected pattern instances
            - penalty (int): Points deducted
        total_penalty (int): Sum of all penalties
    """
    print(f"\n{Colors.YELLOW}Weak Patterns Detected:{Colors.RESET}")
    print(create_separator())
    
    for penalty in penalties:
        # Format instances as comma-separated quoted strings
        instances_str = ', '.join(f"'{p}'" for p in penalty['instances'])
        
        # Print warning with pattern details
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {penalty['type']}: "
              f"{instances_str} (-{penalty['penalty']} pts)")
    
    print(create_separator())
    print(f"{Colors.RED}Total Penalty:{Colors.RESET} -{total_penalty} points")


def print_final_score(final_score: int, strength: str, color: str):
    """
    Displays the final password score and strength rating.
    
    Args:
        final_score (int): Final score after penalties
        strength (str): Strength category (e.g., "STRONG")
        color (str): ANSI color code for the strength
    """
    score_bar = create_score_bar(final_score)
    
    print(f"\n{Colors.BOLD}Final Score:{Colors.RESET} "
          f"{color}{final_score}/100{Colors.RESET}")
    print(f"{Colors.BOLD}Strength:{Colors.RESET} "
          f"{color}{strength}{Colors.RESET}")
    print(f"{score_bar}\n")


def print_common_password_check(is_common: bool, message: str):
    """
    Displays common password database check results.
    
    Args:
        is_common (bool): True if password found in common database
        message (str): Detailed message about the check
    """
    print(f"\n{Colors.CYAN}Common Password Check:{Colors.RESET}")
    print(create_separator())
    
    if is_common:
        # Critical warning if password is common
        print(f"{Colors.RED}[CRITICAL]{Colors.RESET} {message}")
    else:
        # Success if password is not common
        print(f"{Colors.GREEN}[PASS]{Colors.RESET} {message}")

def print_breach_check(is_pwned: bool, message: str):
    """
    Displays Have I Been Pwned breach check results.
    
    Args:
        is_pwned (bool): True if password found in breaches
        message (str): Detailed message about the check
    """
    print(f"\n{Colors.CYAN}Data Breach Check (Have I Been Pwned):{Colors.RESET}")
    print(create_separator())
    
    if is_pwned:
        # Critical warning if password was breached
        print(f"{Colors.RED}[CRITICAL]{Colors.RESET} {message}")
    else:
        # Check if it's a skip/error message
        if "unavailable" in message.lower() or "timed out" in message.lower() or "error" in message.lower():
            print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {message}")
        else:
            # Success if password not found in breaches
            print(f"{Colors.GREEN}[PASS]{Colors.RESET} {message}")

def print_recommendations(recommendations: list[str]):
    """
    Displays password improvement recommendations.
    
    Args:
        recommendations (list): List of recommendation strings
    """
    if not recommendations:
        return
    
    print(f"\n{Colors.CYAN}Recommendations for Improvement:{Colors.RESET}")
    print(create_separator())
    
    for i, recommendation in enumerate(recommendations, 1):
        print(f"{Colors.YELLOW}[{i}]{Colors.RESET} {recommendation}")
    
    print(create_separator())


# ============================================================================
# MAIN RESULTS DISPLAY FUNCTION
# ============================================================================

def print_analysis_results(results: dict):
    """
    Displays comprehensive password analysis results.
    
    This is the main display orchestrator that calls all other display
    functions in the correct order to present a complete analysis.
    
    Args:
        results (dict): Complete analysis results from analyze_password()
            containing checks, scores, entropy, patterns, etc.
    
    Display Flow:
        1. Security checks table
        2. Base score
        3. Entropy analysis
        4. Common password check
        5. Data breach check (Have I Been Pwned)
        6. Weak patterns (if any)
        7. Final score and strength rating
        8. Recommendations (if applicable)
    """
    # Display individual security checks
    print_security_checks(results['checks'])
    
    # Display base score
    print_base_score(results['base_score'])
    
    # Display entropy analysis
    print_entropy_analysis(
        results['entropy'],
        results['entropy_rating'],
        results['entropy_color']
    )
    
    # Display common password check
    print_common_password_check(
        results['is_common'],
        results['common_password_message']
    )
    
    # Display data breach check
    print_breach_check(
        results['is_pwned'],
        results['pwned_message']
    )
    
    # Display weak patterns if detected
    if results['has_weak_patterns'] or results['is_common'] or results['is_pwned']:
        print_weak_patterns(
            results['penalties'],
            results['total_penalty']
        )
    
    # Display final score and strength
    print_final_score(
        results['final_score'],
        results['strength'],
        results['color']
    )
    
    # Display recommendations if any
    if results.get('recommendations'):
        print_recommendations(results['recommendations'])


# ============================================================================
# USER INPUT PROMPTS
# ============================================================================

def get_password_input() -> str:
    """
    Prompts user for password input.
    
    Returns:
        str: User-entered password
    """
    return input(f"{Colors.BOLD}Enter password to check: {Colors.RESET}")


def print_warning(message: str):
    """
    Displays a warning message.
    
    Args:
        message (str): Warning message to display
    """
    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {message}\n")


def print_error(message: str):
    """
    Displays an error message.
    
    Args:
        message (str): Error message to display
    """
    print(f"{Colors.RED}[ERROR]{Colors.RESET} {message}\n")

    