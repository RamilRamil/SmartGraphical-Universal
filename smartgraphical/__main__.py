"""``python -m smartgraphical`` -> the single-shot analyzer CLI."""
import sys

from smartgraphical.interfaces.cli.analyzer import main


if __name__ == "__main__":
    sys.exit(main())
