#!/usr/bin/env python3
import argparse
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN = (
    ".request",
    "http_request",
    ".syn",
    ".Body",
    ".body",
    "capability-token",
    "identifyexecutor",
    "getexecutorname",
    ".debug",
    "getconstants",
    "hookfunction",
    "getfunctionbytecode",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    args = parser.parse_args()

    cases = (
        ("online", (
            "--runtime", "executor",
            "--environment-binding", "portable",
            "--key-mode", "online",
            "--online-key-url", "https://secret.example/v2/key/capability-token",
            "--online-key-material", "hidden-material",
        )),
        ("executor", (
            "--runtime", "executor",
            "--environment-binding", "executor",
        )),
    )

    with tempfile.TemporaryDirectory(prefix="alex-hidden-signatures-") as temporary:
        temp = pathlib.Path(temporary)
        source = temp / "source.luau"
        source.write_text("return 42\n", encoding="utf-8")
        for profile in ("compatibility", "hardened", "maximum"):
            for name, options in cases:
                output = temp / f"{profile}-{name}.luau"
                result = subprocess.run([
                    str(args.alexfuscator), str(source), "-o", str(output),
                    "--profile", profile,
                    "--seed", "991",
                    *options,
                ], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                artifact = output.read_text(encoding="utf-8")
                visible = [signature for signature in FORBIDDEN if signature in artifact]
                if visible:
                    raise RuntimeError(f"visible signatures in {profile}/{name}: {visible}")

    print("Hidden signatures OK: request, executor, and inspector aliases are masked")


if __name__ == "__main__":
    main()
