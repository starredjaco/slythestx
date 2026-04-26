#!/usr/bin/env python3
import sys
from pathlib import Path

try:
    import jsbeautifier
except ImportError:
    print("[!] jsbeautifier not installed. Install with: pip install jsbeautifier")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <bundle.js>")
        sys.exit(1)

    bundle_path = Path(sys.argv[1])

    if not bundle_path.exists():
        print(f"[!] File not found: {bundle_path}")
        sys.exit(1)

    try:
        raw = bundle_path.read_bytes()
        js_code = raw.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Failed to read bundle: {e}")
        sys.exit(1)

    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.preserve_newlines = True
    opts.max_preserve_newlines = 2
    opts.wrap_line_length = 120

    beautified = jsbeautifier.beautify(js_code, opts)

    # Sobrescribir el mismo archivo
    try:
        bundle_path.write_text(beautified, encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Failed to write beautified file: {e}")
        sys.exit(1)

    print(f"[+] Beautified bundle written to: {bundle_path}")


if __name__ == "__main__":
    main()
