#!/usr/bin/env python3
import argparse
import asyncio
import builtins
import json
import shutil
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALT_APP = ROOT / "work" / "external" / "alt-app-installer" / "app"


class DummyEvent:
    def is_set(self):
        return False


class DummyProgress:
    def emit(self, *_args, **_kwargs):
        pass


def product_url(value):
    value = value.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"https://apps.microsoft.com/detail/{value}"


async def generate_links(store_url, ignore_version=False, all_dependencies=False, arch=None):
    sys.path.insert(0, str(ALT_APP))
    real_open = builtins.open

    def portable_open(path, *args, **kwargs):
        if isinstance(path, str) and str(ALT_APP) in path and "\\" in path:
            path = path.replace("\\", "/")
        return real_open(path, *args, **kwargs)

    from modules.url_gen import url_generator
    import aiohttp

    real_session = aiohttp.ClientSession

    def portable_session(*args, **kwargs):
        kwargs.setdefault("connector", aiohttp.TCPConnector(ssl=False))
        return real_session(*args, **kwargs)

    builtins.open = portable_open
    aiohttp.ClientSession = portable_session
    try:
        if arch and arch != "auto":
            import modules.url_gen as url_gen_module
            url_gen_module.os_arc = lambda: arch
        return await url_generator(
            product_url(store_url),
            ignore_version,
            all_dependencies,
            DummyEvent(),
            DummyProgress(),
            DummyProgress(),
            False,
        )
    finally:
        builtins.open = real_open
        aiohttp.ClientSession = real_session


def download_file(url, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=120) as response:
        with dest.open("wb") as out:
            shutil.copyfileobj(response, out)
    return dest.stat().st_size


def main():
    parser = argparse.ArgumentParser(description="Generate/download Microsoft Store package links without the Microsoft Store GUI.")
    parser.add_argument("product", help="Microsoft Store URL or product id, e.g. 9WZDNCRFJ3TJ")
    parser.add_argument("--out", default="outputs/msstore_fetch", help="Output folder")
    parser.add_argument("--download", action="store_true", help="Download generated package URLs")
    parser.add_argument("--all-dependencies", action="store_true", help="Keep all dependency versions/architectures returned by the API")
    parser.add_argument("--ignore-version", action="store_true", help="Do not prefer latest versions")
    parser.add_argument("--arch", default="auto", choices=["auto", "x64", "x86", "arm64"], help="Architecture to select; use x64 for most CrossOver bottles")
    args = parser.parse_args()

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    links, selected, main_file, uwp = asyncio.run(generate_links(args.product, args.ignore_version, args.all_dependencies, args.arch))
    report = {
        "product": product_url(args.product),
        "arch": args.arch,
        "uwp": uwp,
        "main_file": main_file,
        "selected": selected,
        "links": links,
        "downloads": [],
    }

    if args.download:
        download_dir = out_dir / "downloads"
        for name in selected:
            url = links.get(name)
            if not url:
                continue
            print(f"Downloading {name}...")
            size = download_file(url, download_dir / name)
            report["downloads"].append({"name": name, "path": str(download_dir / name), "bytes": size})

    report_path = out_dir / "msstore_fetch_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Report: {report_path}")


if __name__ == "__main__":
    raise SystemExit(main())
