"""CLI entry point for the installed `netlogic` command.

Delegates to the root `netlogic.py` (local web launcher via `--gui`, plus optional helpers).
"""
import os
import sys


def main() -> None:
    # Ensure the project root is on sys.path so netlogic.py can find its imports
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    os.chdir(root)

    import netlogic  # noqa: PLC0415
    netlogic.main()


if __name__ == "__main__":
    main()
