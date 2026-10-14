#!/usr/bin/env python3
"""pepatch - safe patcher for Windows PE executables (PE32 / PE32+).

Design goals (all safety rails, no external dependencies):
  * translate a virtual address (VA) or RVA to a file offset correctly,
    honouring the section table and file alignment;
  * never write a byte without first confirming the *expected* original
    byte is there (guards against patching the wrong build/version);
  * always snapshot the file before the first write of a session;
  * grow the binary with a brand-new section when you need somewhere to
    put added code, fixing up the PE headers so the loader accepts it;
  * append every write to a JSON patch log that `undo` can replay in
    reverse to restore the original bytes exactly.

Nothing here is Windows-specific at runtime; it is byte surgery on a file.
"""

import argparse
import datetime
import json
import os
import shutil
import struct
import sys

# ---------------------------------------------------------------------------
# PE structure constants
# ---------------------------------------------------------------------------
MZ_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"
OPT_HDR_PE32 = 0x10B
OPT_HDR_PE32_PLUS = 0x20B

SECTION_HEADER_SIZE = 40

# Section characteristics flags we set on an injected code section.
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def _align(value, alignment):
    """Round value up to the next multiple of alignment."""
    if alignment == 0:
        return value
    return (value + alignment - 1) // alignment * alignment


class PEError(Exception):
    pass


class Section:
    def __init__(self, raw, index):
        (self.name_raw,
         self.virtual_size,
         self.virtual_address,
         self.size_of_raw_data,
         self.pointer_to_raw_data,
         self.pointer_to_relocations,
         self.pointer_to_linenumbers,
         self.number_of_relocations,
         self.number_of_linenumbers,
         self.characteristics) = struct.unpack("<8sIIIIIIHHI", raw)
        self.index = index

    @property
    def name(self):
        return self.name_raw.rstrip(b"\x00").decode("latin-1")

    def contains_rva(self, rva):
        # Use the larger of virtual_size and raw size so we match the loader's
        # view; a section's mapped size is virtual_size, but pad to raw too.
        span = max(self.virtual_size, self.size_of_raw_data)
        return self.virtual_address <= rva < self.virtual_address + span

    def contains_offset(self, off):
        return (self.pointer_to_raw_data <= off
                < self.pointer_to_raw_data + self.size_of_raw_data)


class PEFile:
    """Minimal read/parse of a PE image, enough for safe patching."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = bytearray(fh.read())
        self._parse()

    # -- parsing ----------------------------------------------------------
    def _parse(self):
        d = self.data
        if d[:2] != MZ_MAGIC:
            raise PEError("not an MZ/PE file (bad DOS magic)")
        self.e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[self.e_lfanew:self.e_lfanew + 4] != PE_MAGIC:
            raise PEError("PE signature not found at e_lfanew")

        coff = self.e_lfanew + 4
        (self.machine,
         self.number_of_sections,
         _timestamp,
         _ptr_symtab,
         _num_syms,
         self.size_of_optional_header,
         self.characteristics) = struct.unpack_from("<HHIIIHH", d, coff)

        self.opt_off = coff + 20
        self.magic = struct.unpack_from("<H", d, self.opt_off)[0]
        if self.magic == OPT_HDR_PE32:
            self.is_pe32_plus = False
        elif self.magic == OPT_HDR_PE32_PLUS:
            self.is_pe32_plus = True
        else:
            raise PEError("unknown optional header magic 0x%X" % self.magic)

        # ImageBase lives at a different offset / width between the two forms.
        if self.is_pe32_plus:
            self.image_base = struct.unpack_from("<Q", d, self.opt_off + 24)[0]
            self._image_base_off = self.opt_off + 24
            self._image_base_fmt = "<Q"
        else:
            self.image_base = struct.unpack_from("<I", d, self.opt_off + 28)[0]
            self._image_base_off = self.opt_off + 28
            self._image_base_fmt = "<I"

        self.section_alignment = struct.unpack_from("<I", d, self.opt_off + 32)[0]
        self.file_alignment = struct.unpack_from("<I", d, self.opt_off + 36)[0]
        # SizeOfImage offset is the same in both header forms (relative to opt).
        self._size_of_image_off = self.opt_off + 56
        self.size_of_image = struct.unpack_from("<I", d, self._size_of_image_off)[0]
        self._size_of_headers_off = self.opt_off + 60
        self.size_of_headers = struct.unpack_from("<I", d, self._size_of_headers_off)[0]

        self.sections = []
        sec_off = self.opt_off + self.size_of_optional_header
        self._section_table_off = sec_off
        for i in range(self.number_of_sections):
            raw = d[sec_off:sec_off + SECTION_HEADER_SIZE]
            self.sections.append(Section(raw, i))
            sec_off += SECTION_HEADER_SIZE

    # -- address translation ---------------------------------------------
    def va_to_rva(self, va):
        return va - self.image_base

    def rva_to_offset(self, rva):
        for s in self.sections:
            if s.contains_rva(rva):
                delta = rva - s.virtual_address
                if delta >= s.size_of_raw_data:
                    raise PEError(
                        "RVA 0x%X is in section %s but beyond its raw data "
                        "(uninitialised region, not present in the file)"
                        % (rva, s.name))
                return s.pointer_to_raw_data + delta
        # RVAs inside the header region map 1:1.
        if rva < self.size_of_headers:
            return rva
        raise PEError("RVA 0x%X is not inside any section" % rva)

    def va_to_offset(self, va):
        return self.rva_to_offset(self.va_to_rva(va))

    def resolve(self, addr, kind):
        if kind == "off":
            return addr
        if kind == "rva":
            return self.rva_to_offset(addr)
        if kind == "va":
            return self.va_to_offset(addr)
        raise PEError("unknown address kind %r" % kind)

    # -- helpers ----------------------------------------------------------
    def read(self, offset, length):
        if offset < 0 or offset + length > len(self.data):
            raise PEError("read 0x%X+%d out of file bounds" % (offset, length))
        return bytes(self.data[offset:offset + length])

    def save(self, path=None):
        path = path or self.path
        with open(path, "wb") as fh:
            fh.write(self.data)


# ---------------------------------------------------------------------------
# Patch log
# ---------------------------------------------------------------------------
def _log_path(target):
    return target + ".patchlog.json"


def _load_log(target):
    p = _log_path(target)
    if os.path.exists(p):
        with open(p) as fh:
            return json.load(fh)
    return {"target": os.path.abspath(target), "backup": None, "entries": []}


def _save_log(target, log):
    with open(_log_path(target), "w") as fh:
        json.dump(log, fh, indent=2)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _ensure_backup(target, log):
    if log.get("backup") and os.path.exists(log["backup"]):
        return log["backup"]
    bak = target + ".bak"
    n = 0
    while os.path.exists(bak):
        n += 1
        bak = "%s.bak%d" % (target, n)
    shutil.copy2(target, bak)
    log["backup"] = os.path.abspath(bak)
    return bak


def _parse_addr(text):
    """Return (value, kind). Prefix va:/rva:/off: or bare = va."""
    kind = "va"
    if ":" in text:
        pfx, text = text.split(":", 1)
        pfx = pfx.lower()
        if pfx in ("va", "rva", "off", "offset"):
            kind = "off" if pfx == "offset" else pfx
        else:
            raise PEError("bad address prefix %r" % pfx)
    return int(text, 0), kind


def _parse_hexbytes(text):
    return bytes.fromhex(text.replace(" ", "").replace(",", ""))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_info(args):
    pe = PEFile(args.file)
    bits = "PE32+" if pe.is_pe32_plus else "PE32"
    print("%s  machine=0x%04X  image_base=0x%X" % (bits, pe.machine, pe.image_base))
    print("section_align=0x%X  file_align=0x%X  size_of_image=0x%X  size_of_headers=0x%X"
          % (pe.section_alignment, pe.file_alignment, pe.size_of_image, pe.size_of_headers))
    print("sections (%d):" % pe.number_of_sections)
    print("  %-9s %-10s %-10s %-10s %-10s %s" %
          ("name", "RVA", "vsize", "rawptr", "rawsize", "flags"))
    for s in pe.sections:
        print("  %-9s 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X"
              % (s.name, s.virtual_address, s.virtual_size,
                 s.pointer_to_raw_data, s.size_of_raw_data, s.characteristics))
    return 0


def cmd_resolve(args):
    pe = PEFile(args.file)
    val, kind = _parse_addr(args.addr)
    off = pe.resolve(val, kind)
    rva = (val if kind == "rva"
           else pe.va_to_rva(val) if kind == "va"
           else None)
    print("input      : %s (%s)" % (hex(val), kind))
    if rva is not None:
        print("RVA        : 0x%X" % rva)
        print("VA         : 0x%X" % (rva + pe.image_base))
    print("file offset: 0x%X (%d)" % (off, off))
    sec = next((s for s in pe.sections if s.contains_offset(off)), None)
    print("section    : %s" % (sec.name if sec else "(headers/none)"))
    return 0


def cmd_read(args):
    pe = PEFile(args.file)
    val, kind = _parse_addr(args.addr)
    off = pe.resolve(val, kind)
    data = pe.read(off, args.length)
    print("off 0x%X: %s" % (off, data.hex(" ")))
    return 0


def cmd_patch(args):
    target = args.file
    pe = PEFile(target)
    val, kind = _parse_addr(args.addr)
    off = pe.resolve(val, kind)
    new = _parse_hexbytes(args.bytes)
    expect = _parse_hexbytes(args.expect) if args.expect else None

    current = pe.read(off, len(new))
    if expect is not None:
        if len(expect) != len(new):
            raise PEError("--expect length (%d) != new bytes length (%d)"
                          % (len(expect), len(new)))
        if current != expect:
            raise PEError(
                "SAFETY STOP: bytes at off 0x%X are %s, expected %s. "
                "Wrong file/version/address - refusing to write."
                % (off, current.hex(" "), expect.hex(" ")))
    elif args.force:
        print("WARNING: --force without --expect; writing blind. Current bytes: %s"
              % current.hex(" "))
    else:
        raise PEError(
            "refusing to patch without --expect (current bytes: %s). "
            "Pass -e/--expect <hex> to verify the original, or --force to "
            "write unverified." % current.hex(" "))

    log = _load_log(target)
    bak = _ensure_backup(target, log)

    pe.data[off:off + len(new)] = new
    pe.save()
    log["entries"].append({
        "time": _now(),
        "type": "patch",
        "offset": off,
        "addr_input": args.addr,
        "before": current.hex(),
        "after": new.hex(),
    })
    _save_log(target, log)
    print("patched off 0x%X: %s -> %s" % (off, current.hex(" "), new.hex(" ")))
    print("backup: %s   log: %s" % (bak, _log_path(target)))
    return 0


def _plan_section_rva(pe):
    """RVA the next added section will receive (independent of its payload)."""
    last_rva_end = max(s.virtual_address + max(s.virtual_size, s.size_of_raw_data)
                       for s in pe.sections)
    return _align(last_rva_end, pe.section_alignment)


def _add_section(pe, name_str, payload, size, writable):
    """Append a section, mutating pe.data and headers in memory.

    Returns the log entry describing the change. Does not save, touch the
    backup, or write the log file - the caller owns that.
    """
    name = name_str.encode("latin-1")
    if len(name) > 8:
        raise PEError("section name max 8 bytes")
    size = max(size, len(payload))
    if size == 0:
        raise PEError("section needs a size or payload")

    # Room in the header for one more 40-byte section entry? It must not
    # overrun the first section's raw data.
    new_hdr_off = pe._section_table_off + pe.number_of_sections * SECTION_HEADER_SIZE
    first_raw = min((s.pointer_to_raw_data for s in pe.sections
                     if s.pointer_to_raw_data > 0), default=pe.size_of_headers)
    if new_hdr_off + SECTION_HEADER_SIZE > first_raw:
        raise PEError(
            "no room in header for another section entry "
            "(hdr end 0x%X would collide with first raw data 0x%X)"
            % (new_hdr_off + SECTION_HEADER_SIZE, first_raw))

    raw_size = _align(size, pe.file_alignment)
    virt_size = size
    file_ptr = _align(len(pe.data), pe.file_alignment)
    virt_addr = _plan_section_rva(pe)

    characteristics = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
                       | IMAGE_SCN_MEM_READ)
    if writable:
        characteristics |= IMAGE_SCN_MEM_WRITE

    hdr = struct.pack("<8sIIIIIIHHI",
                      name.ljust(8, b"\x00"),
                      virt_size, virt_addr, raw_size, file_ptr,
                      0, 0, 0, 0, characteristics)

    before_hdr = bytes(pe.data[new_hdr_off:new_hdr_off + SECTION_HEADER_SIZE])
    old_num_sections = pe.number_of_sections
    old_size_of_image = pe.size_of_image

    pe.data[new_hdr_off:new_hdr_off + SECTION_HEADER_SIZE] = hdr
    struct.pack_into("<H", pe.data, pe.e_lfanew + 4 + 2, old_num_sections + 1)
    new_size_of_image = _align(virt_addr + virt_size, pe.section_alignment)
    struct.pack_into("<I", pe.data, pe._size_of_image_off, new_size_of_image)

    old_eof = len(pe.data)
    if len(pe.data) < file_ptr:
        pe.data.extend(b"\x00" * (file_ptr - len(pe.data)))
    body = bytearray(payload)
    body.extend(b"\x00" * (raw_size - len(body)))
    pe.data.extend(body)

    # Keep the in-memory view consistent for any later op in the same run.
    pe.number_of_sections = old_num_sections + 1
    pe.size_of_image = new_size_of_image

    return {
        "time": _now(),
        "type": "addsection",
        "name": name_str,
        "hdr_offset": new_hdr_off,
        "hdr_before": before_hdr.hex(),
        "old_num_sections": old_num_sections,
        "old_size_of_image": old_size_of_image,
        "appended_at": old_eof,
        "appended_len": len(pe.data) - old_eof,
        "virtual_address": virt_addr,
        "file_offset": file_ptr,
        "raw_size": raw_size,
        "virt_size": virt_size,
        "characteristics": characteristics,
        "image_base": pe.image_base,
    }


def cmd_addsection(args):
    target = args.file
    pe = PEFile(target)
    payload = b""
    if args.data:
        payload = _parse_hexbytes(args.data)
    elif args.data_file:
        with open(args.data_file, "rb") as fh:
            payload = fh.read()

    log = _load_log(target)
    _ensure_backup(target, log)
    entry = _add_section(pe, args.name, payload, args.size, args.writable)
    pe.save()
    log["entries"].append(entry)
    _save_log(target, log)
    print("added section %r:" % args.name)
    print("  RVA 0x%X  (VA 0x%X)" % (entry["virtual_address"],
                                      entry["virtual_address"] + pe.image_base))
    print("  file offset 0x%X  raw size 0x%X  virt size 0x%X"
          % (entry["file_offset"], entry["raw_size"], entry["virt_size"]))
    print("  characteristics 0x%08X" % entry["characteristics"])
    print("backup: %s   log: %s" % (log["backup"], _log_path(target)))
    return 0


# AddressOfEntryPoint (an RVA) sits at optional-header offset +16 in both
# PE32 and PE32+.
AOEP_OFFSET = 16


def cmd_trampoline(args):
    target = args.file
    pe = PEFile(target)

    payload = b""
    if args.data:
        payload = _parse_hexbytes(args.data)
    elif args.data_file:
        with open(args.data_file, "rb") as fh:
            payload = fh.read()

    aoep_off = pe.opt_off + AOEP_OFFSET
    oep_rva = struct.unpack_from("<I", pe.data, aoep_off)[0]
    if oep_rva == 0:
        raise PEError("image has no entry point (AddressOfEntryPoint=0); "
                      "cannot build a trampoline")

    # Plan where the section lands so we can compute the relative jump before
    # the bytes are written. The trampoline is [payload][E9 rel32 -> OEP].
    sec_rva = _plan_section_rva(pe)
    jmp_rva = sec_rva + len(payload)
    rel32 = oep_rva - (jmp_rva + 5)          # E9 is relative to next insn
    if not (-0x80000000 <= rel32 <= 0x7FFFFFFF):
        raise PEError("entry point too far for a rel32 jmp (unexpected in a PE)")
    tramp = payload + b"\xE9" + struct.pack("<i", rel32)

    size = max(args.size, len(tramp))

    log = _load_log(target)
    _ensure_backup(target, log)

    sec_entry = _add_section(pe, args.name, tramp, size, args.writable)
    # sec_entry["virtual_address"] must equal the sec_rva we planned with.
    if sec_entry["virtual_address"] != sec_rva:
        raise PEError("internal: section RVA shifted during build")

    old_entry = struct.pack("<I", oep_rva)
    struct.pack_into("<I", pe.data, aoep_off, sec_rva)

    pe.save()
    log["entries"].append(sec_entry)
    log["entries"].append({
        "time": _now(),
        "type": "setentry",
        "aoep_offset": aoep_off,
        "old_entry_rva": oep_rva,
        "new_entry_rva": sec_rva,
    })
    _save_log(target, log)

    print("trampoline installed:")
    print("  original entry : RVA 0x%X  (VA 0x%X)"
          % (oep_rva, oep_rva + pe.image_base))
    print("  new entry      : RVA 0x%X  (VA 0x%X) -> section %r"
          % (sec_rva, sec_rva + pe.image_base, args.name))
    print("  payload        : %d byte(s), then jmp rel32=%d back to OEP"
          % (len(payload), rel32))
    print("  section raw off: 0x%X  raw size 0x%X"
          % (sec_entry["file_offset"], sec_entry["raw_size"]))
    print("backup: %s   log: %s" % (log["backup"], _log_path(target)))
    print("note: payload runs with the loader's initial register/stack state; "
          "it must preserve what the real entry point needs and fall through "
          "to the appended jmp (do not ret/jmp yourself).")
    return 0


def cmd_log(args):
    log = _load_log(args.file)
    print("target: %s" % log["target"])
    print("backup: %s" % log.get("backup"))
    if not log["entries"]:
        print("(no entries)")
        return 0
    for i, e in enumerate(log["entries"]):
        if e["type"] == "patch":
            print("[%d] %s PATCH off 0x%X  %s -> %s"
                  % (i, e["time"], e["offset"], e["before"], e["after"]))
        elif e["type"] == "setentry":
            print("[%d] %s SETENTRY RVA 0x%X -> 0x%X"
                  % (i, e["time"], e["old_entry_rva"], e["new_entry_rva"]))
        else:
            print("[%d] %s ADDSECTION %r at off 0x%X (RVA 0x%X, +%d bytes)"
                  % (i, e["time"], e["name"], e["appended_at"],
                     e["virtual_address"], e["appended_len"]))
    return 0


def cmd_undo(args):
    target = args.file
    log = _load_log(target)
    if not log["entries"]:
        print("nothing to undo")
        return 0

    with open(target, "rb") as fh:
        data = bytearray(fh.read())

    count = len(log["entries"]) if args.all else 1
    for _ in range(count):
        if not log["entries"]:
            break
        e = log["entries"].pop()
        if e["type"] == "patch":
            off = e["offset"]
            before = bytes.fromhex(e["before"])
            after = bytes.fromhex(e["after"])
            cur = bytes(data[off:off + len(after)])
            if cur != after and not args.force:
                log["entries"].append(e)
                raise PEError(
                    "cannot undo [patch off 0x%X]: current bytes %s != the "
                    "value this entry wrote (%s). File changed since. "
                    "Use --force to restore anyway." % (off, cur.hex(" "), after.hex(" ")))
            data[off:off + len(before)] = before
            print("reverted patch off 0x%X -> %s" % (off, before.hex(" ")))
        elif e["type"] == "setentry":
            struct.pack_into("<I", data, e["aoep_offset"], e["old_entry_rva"])
            print("reverted entry point -> RVA 0x%X" % e["old_entry_rva"])
        elif e["type"] == "addsection":
            # Truncate the appended body, restore the header slot, section
            # count and SizeOfImage.
            del data[e["appended_at"]:e["appended_at"] + e["appended_len"]]
            hdr_off = e["hdr_offset"]
            data[hdr_off:hdr_off + SECTION_HEADER_SIZE] = bytes.fromhex(e["hdr_before"])
            # Re-read count/size offsets from this (now shorter) buffer.
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            struct.pack_into("<H", data, e_lfanew + 4 + 2, e["old_num_sections"])
            opt_off = e_lfanew + 4 + 20
            struct.pack_into("<I", data, opt_off + 56, e["old_size_of_image"])
            print("reverted addsection %r (removed %d bytes)"
                  % (e["name"], e["appended_len"]))

    with open(target, "wb") as fh:
        fh.write(data)
    _save_log(target, log)
    print("done. %d entr%s left in log."
          % (len(log["entries"]), "y" if len(log["entries"]) == 1 else "ies"))
    return 0


def cmd_restore(args):
    target = args.file
    log = _load_log(target)
    bak = log.get("backup")
    if not bak or not os.path.exists(bak):
        raise PEError("no backup recorded in log")
    shutil.copy2(bak, target)
    log["entries"] = []
    _save_log(target, log)
    print("restored %s from %s; log cleared" % (target, bak))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="pepatch",
        description="Safe byte-level patcher for Windows PE executables.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("info", help="dump headers and section table")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("resolve", help="translate va:/rva:/off: to a file offset")
    sp.add_argument("file")
    sp.add_argument("addr", help="e.g. va:0x401000, rva:0x1000, off:0x400")
    sp.set_defaults(func=cmd_resolve)

    sp = sub.add_parser("read", help="read bytes at an address")
    sp.add_argument("file")
    sp.add_argument("addr")
    sp.add_argument("-n", "--length", type=int, default=16)
    sp.set_defaults(func=cmd_read)

    sp = sub.add_parser("patch", help="verify-then-write bytes (backs up + logs)")
    sp.add_argument("file")
    sp.add_argument("addr")
    sp.add_argument("bytes", help="new bytes as hex, e.g. '90 90' or 9090")
    sp.add_argument("-e", "--expect", help="expected original bytes as hex")
    sp.add_argument("--force", action="store_true",
                    help="write even without --expect (unverified)")
    sp.set_defaults(func=cmd_patch)

    sp = sub.add_parser("addsection", help="append a new section for injected code")
    sp.add_argument("file")
    sp.add_argument("--name", default=".newc")
    sp.add_argument("--size", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--data", help="initial contents as hex")
    sp.add_argument("--data-file", help="initial contents from a file")
    sp.add_argument("--writable", action="store_true", help="also set WRITE flag")
    sp.set_defaults(func=cmd_addsection)

    sp = sub.add_parser(
        "trampoline",
        help="redirect the entry point through your code in a new section, "
             "then jmp back to the original entry point")
    sp.add_argument("file")
    sp.add_argument("--name", default=".tramp")
    sp.add_argument("--data", help="payload code as hex (runs before OEP)")
    sp.add_argument("--data-file", help="payload code from a file")
    sp.add_argument("--size", type=lambda x: int(x, 0), default=0,
                    help="min section size (default: just fits the trampoline)")
    sp.add_argument("--writable", action="store_true",
                    help="also set WRITE on the trampoline section")
    sp.set_defaults(func=cmd_trampoline)

    sp = sub.add_parser("log", help="show the patch log")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_log)

    sp = sub.add_parser("undo", help="revert the last patch (or --all)")
    sp.add_argument("file")
    sp.add_argument("--all", action="store_true")
    sp.add_argument("--force", action="store_true",
                    help="restore even if current bytes don't match")
    sp.set_defaults(func=cmd_undo)

    sp = sub.add_parser("restore", help="copy the backup back over the target")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_restore)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (PEError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
