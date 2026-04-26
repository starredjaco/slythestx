"""Unpack Xamarin AssemblyStore files"""

from __future__ import print_function
from builtins import object
import struct
import argparse
import os
import os.path
import sys
import shutil
import lz4.block

"""Global Values"""

# AssemblyStore Constants
ASSEMBLY_STORE_MAGIC = b"XABA"
ASSEMBLY_STORE_FORMAT_VERSION = 1
COMPRESSED_DATA_MAGIC = b"XALZ"

# Assemblies related
FILE_ASSEMBLIES_BLOB = "assemblies.blob"
FILE_ASSEMBLIES_BLOB_ARM = "assemblies.armeabi_v7a.blob"
FILE_ASSEMBLIES_BLOB_ARM_64 = "assemblies.arm64_v8a.blob"
FILE_ASSEMBLIES_BLOB_x86 = "assemblies.x86.blob"
FILE_ASSEMBLIES_BLOB_x86_64 = "assemblies.x86_64.blob"

ARCHITECTURE_MAP = {"arm": FILE_ASSEMBLIES_BLOB_ARM,
                    "arm64": FILE_ASSEMBLIES_BLOB_ARM_64,
                    "x86": FILE_ASSEMBLIES_BLOB_x86,
                    "x86_64": FILE_ASSEMBLIES_BLOB_x86_64}

FILE_ASSEMBLIES_MANIFEST = "assemblies.manifest"

DEBUG = False

def debug(message):
    if DEBUG:
        print("[debug] %s" % message)

class ManifestEntry(object):
    def __init__(self, hash32, hash64, blob_id, blob_idx, name):
        self.hash32 = hash32
        self.hash64 = hash64
        self.blob_id = int(blob_id)
        self.blob_idx = int(blob_idx)
        self.name = name

class ManifestList(list):
    def get_idx(self, blob_id, blob_idx):
        for entry in self:
            if entry.blob_idx == blob_idx and entry.blob_id == blob_id:
                return entry
        return None

class AssemblyStoreAssembly(object):
    pass

class AssemblyStore(object):
    def __init__(self, in_file_name, manifest_entries, primary=True):
        self.manifest_entries = manifest_entries
        self.file_name = os.path.basename(in_file_name)
        blob_file = open(in_file_name, "rb")
        self.raw = blob_file.read()
        blob_file.seek(0)

        magic = blob_file.read(4)
        if magic != ASSEMBLY_STORE_MAGIC:
            raise Exception("Invalid Magic: %s" % magic)

        version = struct.unpack("I", blob_file.read(4))[0]
        if version > ASSEMBLY_STORE_FORMAT_VERSION:
            raise Exception("Version higher than expected! Max = %d, got %d" % (ASSEMBLY_STORE_FORMAT_VERSION, version))

        self.hdr_version = version
        self.hdr_lec = struct.unpack("I", blob_file.read(4))[0]
        self.hdr_gec = struct.unpack("I", blob_file.read(4))[0]
        self.hdr_store_id = struct.unpack("I", blob_file.read(4))[0]

        self.assemblies_list = list()
        for i in range(self.hdr_lec):
            entry = blob_file.read(24)
            assembly = AssemblyStoreAssembly()
            assembly.data_offset = struct.unpack("I", entry[0:4])[0]
            assembly.data_size = struct.unpack("I", entry[4:8])[0]
            self.assemblies_list.append(assembly)

    def extract_all(self, outpath):
        i = 0
        for assembly in self.assemblies_list:
            entry = self.manifest_entries.get_idx(self.hdr_store_id, i)
            if not entry:
                i += 1
                continue

            out_file = os.path.join(outpath, "%s.dll" % entry.name)
            assembly_header = self.raw[assembly.data_offset:assembly.data_offset+4]
            
            if assembly_header == COMPRESSED_DATA_MAGIC:
                assembly_data = self.decompress_lz4(self.raw[assembly.data_offset : assembly.data_offset + assembly.data_size])
            else:
                assembly_data = self.raw[assembly.data_offset : assembly.data_offset + assembly.data_size]

            print("Extracting %s..." % entry.name)
            if not os.path.exists(os.path.dirname(out_file)):
                os.makedirs(os.path.dirname(out_file))

            with open(out_file, "wb") as wfile:
                wfile.write(assembly_data)
            i += 1

    @classmethod
    def decompress_lz4(cls, compressed_data):
        unpacked_payload_len = struct.unpack('<I', compressed_data[8:12])[0]
        compressed_payload = compressed_data[12:]
        return lz4.block.decompress(compressed_payload, uncompressed_size=unpacked_payload_len)

def read_manifest(in_manifest):
    manifest_list = ManifestList()
    with open(in_manifest, "r") as f:
        for line in f:
            if not line.strip() or line.startswith("Hash"):
                continue
            split_line = line.split()
            if len(split_line) >= 5:
                manifest_list.append(ManifestEntry(split_line[0], split_line[1], split_line[2], split_line[3], split_line[4]))
    return manifest_list

def do_unpack(in_directory, in_arch, out_directory):
    # Sobreescritura automática: si existe, se borra
    if os.path.isdir(out_directory):
        debug("Directorio existente. Borrando para sobreescribir...")
        shutil.rmtree(out_directory)

    manifest_path = os.path.join(in_directory, FILE_ASSEMBLIES_MANIFEST)
    assemblies_path = os.path.join(in_directory, FILE_ASSEMBLIES_BLOB)

    if not os.path.isfile(manifest_path) or not os.path.isfile(assemblies_path):
        print("Error: No se encontró el blob o manifiesto en %s" % in_directory)
        return 4

    manifest_entries = read_manifest(manifest_path)
    os.makedirs(out_directory)

    assembly_store = AssemblyStore(assemblies_path, manifest_entries)
    arch_assemblies = (assembly_store.hdr_lec != assembly_store.hdr_gec)

    # Extraer archivos (Sin generar JSON)
    assembly_store.extract_all(out_directory)

    if arch_assemblies:
        arch_path = os.path.join(in_directory, ARCHITECTURE_MAP[in_arch])
        if os.path.exists(arch_path):
            arch_store = AssemblyStore(arch_path, manifest_entries, primary=False)
            arch_store.extract_all(out_directory)
    
    print("\nCompletado. DLLs extraídas en: %s" % out_directory)

def main():
    parser = argparse.ArgumentParser(prog='pyxamstore')
    subparsers = parser.add_subparsers(dest='mode')

    unpack_parser = subparsers.add_parser('unpack', help='Unpack assembly blobs.')
    unpack_parser.add_argument('--dir', '-d', type=str, default='./', dest='directory')
    unpack_parser.add_argument('--arch', '-a', type=str, default='arm64', dest='architecture')
    unpack_parser.add_argument('output_name', type=str, help='Nombre del directorio de salida.')

    args = parser.parse_args()

    if args.mode == 'unpack':
        return do_unpack(args.directory, args.architecture, args.output_name)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
