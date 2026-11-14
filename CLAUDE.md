# Project policy

## Scripts are Python, not shell

Do not add or modify `.sh` files. Write tooling scripts (CI checks, helpers)
in Python, using only the standard library and running on Linux, macOS and
Windows, and call them from CI with `python3 path/to/script.py`. To change an
existing shell script, convert it to Python instead of editing it. One-line
commands inside a workflow's `run:` step are not script files and may stay.
