import os
import re
import sys
import hashlib
import json
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

# ----------------------------
# Helpers
# ----------------------------

def safe_open_elf(path):
    try:
        f = open(path, "rb")
        return ELFFile(f)
    except ELFError:
        return None


def is_macho(path):
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            return magic in (
                b"\xfe\xed\xfa\xce",
                b"\xfe\xed\xfa\xcf",
                b"\xca\xfe\xba\xbe",
                b"\xce\xfa\xed\xfe",
                b"\xcf\xfa\xed\xfe",
            )
    except Exception:
        return False


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(8192), b""):
            h.update(c)
    return h.hexdigest()


# ----------------------------
# ANDROID (UNCHANGED)
# ----------------------------

def extract_snapshot_info(libapp_path):
    with open(libapp_path, "rb") as f:
        elf = ELFFile(f)

        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            return None, [], elf

        syms = dynsym.get_symbol_by_name("_kDartVmSnapshotData")
        if not syms:
            return None, [], elf

        sym = syms[0]
        f.seek(sym["st_value"] + 20)

        snapshot_hash = f.read(32).decode(errors="ignore")
        flags_raw = f.read(256)
        flags = flags_raw.split(b"\0")[0].decode(errors="ignore").split()

        return snapshot_hash, flags, elf


def extract_libflutter_info(libflutter_path):
    elf = safe_open_elf(libflutter_path)
    if elf is None:
        return None, [], "unknown", "android"

    arch = "arm64" if elf.header.e_machine == "EM_AARCH64" else "unknown"

    rodata = elf.get_section_by_name(".rodata")
    if not rodata:
        return None, [], arch, "android"

    data = rodata.data()

    engine_ids = [
        h.decode()
        for h in re.findall(b"\x00([a-f0-9]{40})(?=\x00)", data)
    ]

    dart_version = None
    marker = data.find(b" (stable) (")
    if marker != -1:
        start = data.rfind(b"\x00", 0, marker) + 1
        dart_version = data[start:marker].decode(errors="ignore")

    return dart_version, engine_ids, arch, "android"


def has_debug_sections(elf):
    if elf is None:
        return False
    try:
        for s in elf.iter_sections():
            if s.name and s.name.startswith(".debug"):
                return True
    except Exception:
        pass
    return False


def infer_build_mode(flags):
    if "product" in flags:
        return "release"
    if "profile" in flags:
        return "profile"
    return "debug"


def infer_obfuscation(flags, elf):
    if "product" not in flags:
        return "no"
    if "no-dwarf_stack_traces_mode" in flags and not has_debug_sections(elf):
        return "yes"
    return "unknown"


# ----------------------------
# iOS REAL ANALYSIS
# ----------------------------

def find_ios_flutter_bins(root):
    app = None
    engine = None

    for r, _, files in os.walk(root):
        for f in files:
            if f == "App" and r.endswith("App.framework"):
                app = os.path.join(r, f)
            if f == "Flutter" and r.endswith("Flutter.framework"):
                engine = os.path.join(r, f)

    return app, engine


def extract_ios_snapshot(app_bin):
    with open(app_bin, "rb") as f:
        data = f.read()

    m = re.search(rb"Dart snapshot[A-Za-z0-9_\- ]+", data)
    if not m:
        return None

    return hashlib.sha1(m.group(0)).hexdigest()


def extract_ios_dart_version(engine_bin):
    with open(engine_bin, "rb") as f:
        data = f.read()

    m = re.search(rb"Dart VM version: ([^\x00]+)", data)
    if m:
        return m.group(1).decode(errors="ignore")

    return None


def infer_ios_obfuscation(app_bin):
    with open(app_bin, "rb") as f:
        data = f.read()

    has_symbols = b"Dart_" in data or b"dart::" in data
    return "yes" if not has_symbols else "no"


# ----------------------------
# Main analyzer
# ----------------------------

def analyze_flutter(libdir):
    libapp = os.path.join(libdir, "libapp.so")
    libflutter = os.path.join(libdir, "libflutter.so")

    # ANDROID
    if os.path.exists(libapp) and os.path.exists(libflutter):
        snapshot_hash, flags, elf = extract_snapshot_info(libapp)
        dart_version, engine_ids, arch, _ = extract_libflutter_info(libflutter)

        return {
            "platform": "android",
            "dart_version": dart_version,
            "snapshot_hash": snapshot_hash,
            "flags": flags,
            "arch": arch,
            "build_mode": infer_build_mode(flags),
            "obfuscation": infer_obfuscation(flags, elf),
        }

    # iOS
    app_bin, engine_bin = find_ios_flutter_bins(libdir)
    if app_bin and engine_bin:
        return {
            "platform": "ios",
            "dart_version": extract_ios_dart_version(engine_bin),
            "snapshot_hash": extract_ios_snapshot(app_bin),
            "engine_fingerprint": sha256(engine_bin),
            "obfuscation": infer_ios_obfuscation(app_bin),
        }

    raise FileNotFoundError("No Flutter Android or iOS binaries found")


# ----------------------------
# CLI
# ----------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python extract_dart_info.py <carpeta>")
        sys.exit(1)

    print(json.dumps(analyze_flutter(sys.argv[1])))

