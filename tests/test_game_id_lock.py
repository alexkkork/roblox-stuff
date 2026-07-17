#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
GAME_ID = "123456789"


def run(command, *, check=True):
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\n{result.stderr}")
    return result


def execute(runtime, script, output_dir):
    result = run([
        str(runtime),
        "--luraph-mode", "off",
        "--analysis-hooks", "off",
        "--network-policy", "offline",
        "--out", str(output_dir),
        str(script),
    ])
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="alex-game-lock-") as temporary:
        temp = pathlib.Path(temporary)
        source = temp / "source.luau"
        generated = temp / "locked.luau"
        report = temp / "report.json"
        source.write_text('print("__GAME_LOCK_OK__")\n', encoding="utf-8")
        run([
            str(args.alexfuscator), str(source), "-o", str(generated),
            "--profile", "maximum",
            "--runtime", "universal",
            "--environment-binding", "portable",
            "--game-id", GAME_ID,
            "--seed", "777",
            "--format", "one-line",
            "--report", str(report),
            "--no-watermark",
        ])

        artifact = generated.read_text(encoding="utf-8")
        if GAME_ID in artifact or "GameId" in artifact:
            raise RuntimeError("game lock leaked readable universe metadata")
        descriptor = json.loads(report.read_text(encoding="utf-8"))
        if descriptor.get("game_id_lock") is not True or descriptor.get("game_id_guard_bound") is not True:
            raise RuntimeError("game lock was not represented in the safe report")
        if GAME_ID in report.read_text(encoding="utf-8"):
            raise RuntimeError("safe report leaked the universe ID")

        missing = execute(args.runtime, generated, temp / "run-missing")
        if "__GAME_LOCK_OK__" in missing:
            raise RuntimeError("game lock ran without a game environment")

        matching = temp / "matching.luau"
        matching.write_text(f"game = {{GameId = {GAME_ID}}}\n{artifact}", encoding="utf-8")
        if "__GAME_LOCK_OK__" not in execute(args.runtime, matching, temp / "run-matching"):
            raise RuntimeError("game lock rejected the matching universe")

        mismatched = temp / "mismatched.luau"
        mismatched.write_text(f"game = {{GameId = {int(GAME_ID) + 1}}}\n{artifact}", encoding="utf-8")
        if "__GAME_LOCK_OK__" in execute(args.runtime, mismatched, temp / "run-mismatched"):
            raise RuntimeError("game lock accepted a different universe")

        for invalid in ("0", "not-a-game", "9007199254740992"):
            result = run([str(args.alexfuscator), str(source), "-o", str(temp / "invalid.luau"), "--game-id", invalid], check=False)
            if result.returncode == 0:
                raise RuntimeError(f"invalid game ID was accepted: {invalid}")

    print("Game ID lock OK: matching universe runs; missing and mismatched universes decoy")


if __name__ == "__main__":
    main()
