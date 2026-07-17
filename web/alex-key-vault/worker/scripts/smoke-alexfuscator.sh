#!/bin/sh
set -eu

binary="${1:-/app/bin/alexfuscator}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

compile_and_check() {
    language="$1"
    source="$2"
    marker="$3"
    artifact="$scratch/$language.luau"
    report="$scratch/$language-report.json"

    printf '%s\n' "$source" | "$binary" \
        --stdin \
        --stdout \
        --language "$language" \
        --profile compatibility \
        --seed 6006 \
        --report "$report" \
        >"$artifact"

    test -s "$artifact"
    test -s "$report"
    grep -Fq '"report_version": 4' "$report"
    grep -Fq '"backend": "alexvm6"' "$report"
    grep -Fq '"vm_version": 6' "$report"
    grep -Fq '"ir_version": 2' "$report"
    grep -Fq "\"language\": \"$language\"" "$report"
    if grep -Fq "$marker" "$artifact"; then
        echo "Alexfuscator smoke test leaked a protected source literal" >&2
        return 1
    fi

    if grep -Fq 'loadstring' "$artifact"; then
        echo "Alexfuscator smoke test found a forbidden source loader" >&2
        return 1
    fi
}

compile_and_check luau 'print("docker_luau_vm6")' docker_luau_vm6
compile_and_check alex 'let value = 40 + 2
print(`docker_alex_vm6 {value}`)' docker_alex_vm6

echo "Alexfuscator VM6 Linux smoke test passed"
