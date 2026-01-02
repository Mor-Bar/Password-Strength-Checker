"""
Package Entry Point
==================
Allows running the package as: python -m src

This is the standard Python way to make a package executable.
"""

from .password_checker import main

if __name__ == "__main__":
    main()