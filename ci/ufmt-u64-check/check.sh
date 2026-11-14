#!/bin/sh
# Builds the check object for a core without a 64-bit divider and fails if the ufmt encoder calls
# a 64-bit division helper, or if the control (ufmt's own u64 formatting) does not.
set -eu
cd "$(dirname "$0")"
target=thumbv6m-none-eabi
helpers='__aeabi_uldivmod|__udivdi3|__umoddi3|__udivmoddi4'
nm="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-nm"

symbols() {
    rm -rf target/obj
    cargo rustc --quiet --release --target "$target" --target-dir target/obj "$@" -- --emit=obj
    # rustc names the object differently per host; there is exactly one.
    objects="$(find target/obj/$target/release -name '*.o')"
    if [ "$(printf '%s
' "$objects" | grep -c .)" -ne 1 ]; then
        printf 'expected one object file, found:
%s
' "$objects" >&2
        exit 1
    fi
    "$nm" "$objects"
}

encoder="$(symbols)"
if ! printf '%s
' "$encoder" | grep -Eq ' T report_wide$'; then
    printf 'the check object does not define report_wide:
%s
' "$encoder" >&2
    exit 1
fi
if printf '%s\n' "$encoder" | grep -Eq "$helpers"; then
    printf 'the ufmt encoder calls a 64-bit division helper on %s:\n%s\n' "$target" "$encoder" >&2
    exit 1
fi
control="$(symbols --features control)"
if ! printf '%s\n' "$control" | grep -Eq "$helpers"; then
    printf 'the control did not call a 64-bit division helper on %s; the check proves nothing\n' "$target" >&2
    exit 1
fi
printf 'ufmt encoder: no 64-bit division helper on %s (control calls one)\n' "$target"
