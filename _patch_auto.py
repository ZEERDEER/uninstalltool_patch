#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Uninstall Tool -- version-independent local-license patcher (signature based).

Does not hard-code file offsets: it locates the patch sites through the PE
headers and the .pdata function table, so a new build can be patched by simply
re-running it. If the code shape no longer matches, it stops without writing.

Usage:
    python _patch_auto.py --file <UninstallTool.exe>          # patch (auto backup)
    python _patch_auto.py --file <UninstallTool.exe> --dry-run
"""
import argparse
import hashlib
import os
import re
import shutil
import struct
import sys

EXE = r"D:\App\Uninstall Tool\UninstallTool.exe"

# license-state getter body:
#   lea rcx,[rip+global] ; call <lookup>
#   mov rdx,rax ; mov rcx,rbx ; mov rsi,rax ; call <invoke>
RE_STATE_BODY = re.compile(
    rb"\x48\x8D\x0D....\xE8....\x48\x8B\xD0\x48\x8B\xCB\x48\x8B\xF0\xE8", re.S
)
# cmp eax,3 ; je rel32
RE_CMP_JE = b"\x83\xF8\x03\x0F\x84"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


class PE:
    def __init__(self, data):
        self.d = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE file")
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e:e + 4] != b"PE\0\0":
            raise ValueError("bad PE signature")
        coff = e + 4
        nsec, = struct.unpack_from("<H", data, coff + 2)
        opt_size, = struct.unpack_from("<H", data, coff + 16)
        opt = coff + 20
        magic, = struct.unpack_from("<H", data, opt)
        if magic != 0x20B:
            raise ValueError("only PE32+ is supported")
        self.image_base, = struct.unpack_from("<Q", data, opt + 24)
        self.sections = []
        sec = opt + opt_size
        for i in range(nsec):
            o = sec + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((name, vaddr, vsize, roff, rsize))
        ndd, = struct.unpack_from("<I", data, opt + 108)
        self.dirs = []
        for i in range(ndd):
            rva, size = struct.unpack_from("<II", data, opt + 112 + i * 8)
            self.dirs.append((rva, size))

    def rva_to_off(self, rva):
        for name, vaddr, vsize, roff, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                if rva - vaddr < rsize:
                    return roff + (rva - vaddr)
        return None

    def off_to_rva(self, off):
        for name, vaddr, vsize, roff, rsize in self.sections:
            if roff <= off < roff + rsize:
                return vaddr + (off - roff)
        return None

    def pdata_functions(self):
        if len(self.dirs) <= 3:
            return []
        rva, size = self.dirs[3]
        off = self.rva_to_off(rva)
        if off is None or not size:
            return []
        out = []
        for i in range(size // 12):
            b, e, u = struct.unpack_from("<III", self.d, off + i * 12)
            if b and e > b:
                out.append((b, e))
        out.sort()
        return out

    @staticmethod
    def func_containing(rva, funcs):
        for b, e in funcs:
            if b <= rva < e:
                return b, e
        return None


def candidates(pe, body, toff):
    """all plausible license-state getter function RVAs"""
    funcs = pe.pdata_functions()
    seen = []
    for m in RE_STATE_BODY.finditer(body):
        rva = pe.off_to_rva(toff + m.start())
        rng = pe.func_containing(rva, funcs)
        if not rng:
            continue
        start, end = rng
        if end - start > 0x200:          # getter is tiny
            continue
        if start not in seen:
            seen.append(start)
    return seen, funcs


def sites_for(pe, body, toff, funcs, state_rva):
    """call-site offsets that call a thunk of state_rva and are followed by cmp eax,3 / je"""
    thunks = set()
    for mm in re.finditer(rb"\xE9....", body):
        rel, = struct.unpack_from("<i", body, mm.start() + 1)
        tgt = pe.off_to_rva(toff + mm.start()) + 5 + rel
        if tgt == state_rva:
            thunks.add(pe.off_to_rva(toff + mm.start()))
    if not thunks:
        return {}
    out = {}
    for mm in re.finditer(rb"\xE8....", body):
        rel, = struct.unpack_from("<i", body, mm.start() + 1)
        tgt = pe.off_to_rva(toff + mm.start()) + 5 + rel
        if tgt not in thunks:
            continue
        after = mm.start() + 5
        if body[after:after + len(RE_CMP_JE)] != RE_CMP_JE:
            continue
        off = toff + mm.start()
        rng = pe.func_containing(pe.off_to_rva(off), funcs)
        if rng:
            out.setdefault(rng, []).append(off)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=EXE)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    path = args.file
    if not os.path.exists(path):
        sys.exit("not found: " + path)
    data = bytearray(open(path, "rb").read())
    pe = PE(bytes(data))

    text = [s for s in pe.sections if s[0] == ".text"]
    if not text:
        sys.exit("no .text section")
    _, tvaddr, _, toff, tsize = text[0]
    body = bytes(data[toff:toff + tsize])

    cands, funcs = candidates(pe, body, toff)
    if not cands:
        sys.exit("SIGNATURE MISS: license-state getter not found "
                 "(build too different, or already patched)")

    chosen = None
    for st in cands:
        groups = sites_for(pe, body, toff, funcs, st)
        if not groups:
            continue
        (fstart, fend), sites = max(groups.items(), key=lambda kv: kv[0][1] - kv[0][0])
        if len(sites) != 1:
            continue
        je_off = sites[0] + 5 + 3
        if body[je_off - toff:je_off - toff + 2] != b"\x0F\x84":
            continue
        chosen = (st, je_off, sites[0], (fstart, fend))
        break

    if not chosen:
        sys.exit("SIGNATURE MISS: no unambiguous site "
                 "(build too different, or already patched)")

    state_rva, je_off, call_off, frng = chosen
    state_off = pe.rva_to_off(state_rva)
    je_rva = pe.off_to_rva(je_off)
    call_rva = pe.off_to_rva(call_off)

    print("image base       : 0x%X" % pe.image_base)
    print("state getter     : RVA 0x%X  file 0x%X" % (state_rva, state_off))
    print("check-registration: RVA 0x%X-0x%X" % frng)
    print("call site        : RVA 0x%X" % call_rva)
    print("portable branch  : RVA 0x%X  file 0x%X" % (je_rva, je_off))
    print("bytes before     : state=%s  je=%s" %
          (bytes(data[state_off:state_off + 6]).hex(" "),
           bytes(data[je_off:je_off + 6]).hex(" ")))

    if bytes(data[state_off:state_off + 6]) == b"\xB8\x03\x00\x00\x00\xC3":
        print("ALREADY PATCHED")
        return
    if args.dry_run:
        print("dry-run: nothing written")
        return

    bak = path + ".orig"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print("backup           : " + bak)

    data[je_off:je_off + 6] = b"\x90" * 6
    data[state_off:state_off + 6] = b"\xB8\x03\x00\x00\x00\xC3"
    open(path, "wb").write(bytes(data))
    print("patched sha256   : " + sha256(path))
    print("original sha256  : " + sha256(bak))
    print("done. registry RN/RC still required (base64 of UTF-16LE XOR 0x89).")


if __name__ == "__main__":
    main()
