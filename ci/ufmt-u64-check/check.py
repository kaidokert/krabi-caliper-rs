#!/usr/bin/env python3
"""Fail if the ufmt encoder calls a 64-bit division helper on a core without a 64-bit divider.

Builds the check crate as an object for thumbv6m-none-eabi and reads its symbols with the
toolchain's llvm-nm. The control build (ufmt's own u64 formatting) must call a helper, which
shows the check can fail.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

TARGET = "thumbv6m-none-eabi"
HELPERS = re.compile(r"__aeabi_uldivmod|__udivdi3|__umoddi3|__udivmoddi4")
HERE = Path(__file__).resolve().parent
OBJ_DIR = HERE / "target" / "obj"


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, cwd=HERE).stdout


def llvm_nm():
    sysroot = run(["rustc", "--print", "sysroot"]).strip()
    host = re.search(r"^host: (\S+)$", run(["rustc", "-vV"]), re.MULTILINE).group(1)
    tools = Path(sysroot) / "lib" / "rustlib" / host / "bin"
    return next(tools.glob("llvm-nm*"))


def symbols(nm, *features):
    shutil.rmtree(OBJ_DIR, ignore_errors=True)
    subprocess.run(
        ["cargo", "rustc", "--quiet", "--release", "--target", TARGET,
         "--target-dir", str(OBJ_DIR), *features, "--", "--emit=obj"],
        check=True, cwd=HERE,
    )
    # rustc names the object differently per host; there is exactly one.
    objects = list((OBJ_DIR / TARGET / "release").rglob("*.o"))
    if len(objects) != 1:
        sys.exit(f"expected one object file, found: {objects}")
    return run([str(nm), str(objects[0])])


def main():
    nm = llvm_nm()
    encoder = symbols(nm)
    if not re.search(r" T report_wide$", encoder, re.MULTILINE):
        sys.exit(f"the check object does not define report_wide:\n{encoder}")
    if HELPERS.search(encoder):
        sys.exit(f"the ufmt encoder calls a 64-bit division helper on {TARGET}:\n{encoder}")
    if not HELPERS.search(symbols(nm, "--features", "control")):
        sys.exit(f"the control did not call a 64-bit division helper on {TARGET}")
    print(f"ufmt encoder: no 64-bit division helper on {TARGET} (control calls one)")


if __name__ == "__main__":
    main()
