#!/usr/bin/env python3
"""Replay the code signatures of a signed Electrum.app onto an unsigned build of the same app.

The release app is codesigned and notarized by the release manager. Signing changes only:
- in each Mach-O file, the signature at the end of the file, and three header fields that
  depend on its size: LC_CODE_SIGNATURE's datasize, and __LINKEDIT's filesize and vmsize;
- the files in _CodeSignature/ directories, and Contents/CodeResources (the notarization ticket).

'extract' copies these from the release app into a directory, and 'apply' writes them into a copy
of a builder's unsigned app. If both apps come from the same source, the result is byte-identical
to the release app, which 'manifest' (one line per file) shows.

Only thin 64-bit Mach-O files are supported: Electrum ships one app per architecture.
Uses only the Python standard library, so it also runs on Linux.

usage: codesign_replay.py extract <signed .app> <signature dir>
       codesign_replay.py apply <signature dir> <unsigned .app>   (modifies the app)
       codesign_replay.py manifest <.app>
"""

import hashlib
import os
import stat
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
# codesign on macOS >= 12 sets __LINKEDIT's vmsize to its filesize rounded up to 16 KiB, for both
# architectures. The vmsize can therefore shrink as well as grow. (cctools' codesign_allocate, which
# the previous scripts used, only grows it, so its replay can differ from what codesign wrote.)
LINKEDIT_VMSIZE_ALIGN = 0x4000
SIG_SUFFIX = ".sign"


class ReplayError(Exception):
    pass


def is_macho(path):
    """True for a thin 64-bit little-endian Mach-O file."""
    with open(path, "rb") as f:
        return f.read(4) == struct.pack("<I", MH_MAGIC_64)


class MachO:
    """The signature-related fields of a thin 64-bit little-endian Mach-O file."""

    def __init__(self, data, path):
        self.path = path
        ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
        self.sig_cmd = None       # offset of the LC_CODE_SIGNATURE load command
        self.linkedit_cmd = None  # offset of the __LINKEDIT LC_SEGMENT_64 load command
        off = 32  # sizeof(struct mach_header_64)
        end = off + sizeofcmds
        if end > len(data):
            raise ReplayError(f"{path}: unexpected Mach-O layout")
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmdsize < 8 or off + cmdsize > end:
                raise ReplayError(f"{path}: unexpected Mach-O layout")
            if cmd == LC_SEGMENT_64 and data[off + 8:off + 24].rstrip(b"\0") == b"__LINKEDIT":
                self.linkedit_cmd = off
            elif cmd == LC_CODE_SIGNATURE:
                self.sig_cmd = off
            off += cmdsize
        if off != end or self.linkedit_cmd is None:
            raise ReplayError(f"{path}: unexpected Mach-O layout")
        self.data = data

    # struct linkedit_data_command: cmd, cmdsize, dataoff, datasize (uint32 each)
    def sig_range(self):
        dataoff, datasize = struct.unpack_from("<II", self.data, self.sig_cmd + 8)
        return dataoff, datasize

    def set_signature(self, blob):
        """Replace the signature, keeping its offset, and update the three dependent fields."""
        if self.sig_cmd is None:
            raise ReplayError(f"{self.path}: has no signature to replace (the unsigned build is ad-hoc signed)")
        dataoff, datasize = self.sig_range()
        # struct segment_command_64: cmd, cmdsize, segname[16], vmaddr, vmsize, fileoff, filesize, ...
        fileoff, = struct.unpack_from("<Q", self.data, self.linkedit_cmd + 40)
        if dataoff + datasize != len(self.data) or dataoff < fileoff:
            raise ReplayError(f"{self.path}: the signature is not at the end of __LINKEDIT")
        filesize = dataoff + len(blob) - fileoff
        vmsize = -(-filesize // LINKEDIT_VMSIZE_ALIGN) * LINKEDIT_VMSIZE_ALIGN
        del self.data[dataoff:]
        self.data += blob
        struct.pack_into("<I", self.data, self.sig_cmd + 12, len(blob))
        struct.pack_into("<Q", self.data, self.linkedit_cmd + 32, vmsize)
        struct.pack_into("<Q", self.data, self.linkedit_cmd + 48, filesize)


def walk(root):
    """Relative paths of all entries below root, sorted, without following symlinks."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


def is_signing_file(rel):
    """Files that signing or notarization (stapling) write, besides the Mach-O signatures."""
    return "_CodeSignature" in rel.split(os.sep) or rel == os.path.join("Contents", "CodeResources")


def app_path(app, rel):
    """app/rel. Refuses paths that would lead out of the app's own tree through a symlink."""
    path = os.path.join(app, rel)
    if os.path.realpath(path) != os.path.join(os.path.realpath(app), rel):
        raise ReplayError(f"{path}: is a symlink, or inside a symlinked directory")
    return path


def write_file(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def extract(app, sigdir):
    if os.path.exists(sigdir):
        raise ReplayError(f"{sigdir} exists")
    n_sigs = n_files = 0
    for rel in walk(app):
        path = os.path.join(app, rel)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        if is_signing_file(rel):
            with open(path, "rb") as f:
                write_file(os.path.join(sigdir, rel), f.read(), stat.S_IMODE(os.lstat(path).st_mode))
            n_files += 1
        elif is_macho(path):
            with open(path, "rb") as f:
                macho = MachO(bytearray(f.read()), path)
            if macho.sig_cmd is None:
                continue
            dataoff, datasize = macho.sig_range()
            write_file(os.path.join(sigdir, rel + SIG_SUFFIX), macho.data[dataoff:dataoff + datasize])
            n_sigs += 1
    print(f"extracted {n_sigs} Mach-O signatures and {n_files} other signing files", file=sys.stderr)


def apply(sigdir, app):
    """Only replaces signatures and signing files that the (ad-hoc signed) build already has, and
    adds the notarization ticket. Anything else in the signed app is reported by 'manifest'."""
    n_sigs = n_files = 0
    for rel in walk(sigdir):
        src = os.path.join(sigdir, rel)
        if not os.path.isfile(src):
            continue
        with open(src, "rb") as f:
            blob = f.read()
        if rel.endswith(SIG_SUFFIX):
            path = app_path(app, rel[:-len(SIG_SUFFIX)])
            if not os.path.isfile(path) or not is_macho(path):
                raise ReplayError(f"{path}: missing, or not a Mach-O file")
            with open(path, "rb") as f:
                macho = MachO(bytearray(f.read()), path)
            macho.set_signature(blob)
            mode = stat.S_IMODE(os.lstat(path).st_mode)
            write_file(path, macho.data, mode)
            n_sigs += 1
        else:
            path = app_path(app, rel)
            ticket = rel == os.path.join("Contents", "CodeResources")
            if not is_signing_file(rel) or not (os.path.isfile(path) or ticket):
                raise ReplayError(f"{path}: the signed app has this file, the build does not")
            write_file(path, blob, stat.S_IMODE(os.lstat(src).st_mode))
            n_files += 1
    print(f"applied {n_sigs} Mach-O signatures and {n_files} other signing files", file=sys.stderr)


def manifest(app):
    """One line per entry: type, permission bits, and the sha256 (files) or target (symlinks).

    Symlinks are listed without permission bits, which Linux shows as 0777 and macOS uses only for
    readlink(). Names and targets that would make a line ambiguous are refused: control characters
    (a newline could fake or hide lines), and " ->" in a symlink name.
    """
    def has_control_chars(s):
        return any(c < " " or c == "\x7f" for c in s)

    print(f"d {stat.S_IMODE(os.lstat(app).st_mode):04o} .")
    for rel in walk(app):
        path = os.path.join(app, rel)
        if has_control_chars(rel):
            raise ReplayError(f"{path!r}: control character in the name")
        st = os.lstat(path)
        mode = f"{stat.S_IMODE(st.st_mode):04o}"
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(path)
            if " ->" in rel or has_control_chars(target):
                raise ReplayError(f"{path!r}: symlink name or target cannot be listed unambiguously")
            print(f"l {rel} -> {target}")
        elif stat.S_ISDIR(st.st_mode):
            print(f"d {mode} {rel}")
        elif stat.S_ISREG(st.st_mode):
            with open(path, "rb") as f:
                print(f"f {mode} {hashlib.sha256(f.read()).hexdigest()} {rel}")
        else:
            print(f"? {mode} {rel}")


def main():
    commands = {"extract": extract, "apply": apply, "manifest": manifest}
    cmd, *args = sys.argv[1:] or [None]
    if cmd not in commands or len(args) != (1 if cmd == "manifest" else 2):
        sys.exit(__doc__)
    for d in args if cmd == "apply" else args[:1]:  # the app, and apply's signature dir
        # a symlink to a directory would be followed, e.g. to another app
        if os.path.islink(os.path.normpath(d)) or not os.path.isdir(d):
            sys.exit(f"codesign_replay.py: {d} is not a directory (or is a symlink)")
    try:
        commands[cmd](*args)
    except ReplayError as e:
        sys.exit(f"codesign_replay.py: {e}")


if __name__ == "__main__":
    main()
