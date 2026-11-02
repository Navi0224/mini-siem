"""Allow ``python -m mini_siem ...`` as an alternative to the ``mini-siem`` script."""

from mini_siem.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
