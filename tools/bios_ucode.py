#!/usr/bin/env python3
"""
bios_ucode.py - audit / patch / verify Intel microcode inside an AMI Aptio UEFI image.

Standard library only. Designed for "Jetway TI61M5.bin" (4 MiB SPI dump), but works on any
image that stores CPU microcode in the AMI microcode FFS file
(GUID 17088572-377F-44EF-8F4E-B09FFF46A070), including copies that live inside an
LZMA-compressed section (as the DXE copy does on this board).

Commands
  audit    IMAGE                         list every microcode FFS copy and its patches
  patch    IMAGE --ucode-dir DIR -o OUT  replace microcode with newer revisions (same size only)
  verify   ORIGINAL PATCHED              check the patched image is structurally sane
  selftest IMAGE                         fabricate a newer 306A9 patch and run patch+verify on it

Nothing here changes the layout of the image: replacements are in place, same size, and the
FFS checksums are recomputed. A patch whose size differs from the slot is reported and skipped.
"""
import argparse
import hashlib
import lzma
import os
import struct
import sys
import tempfile
import uuid

GUID_UCODE = uuid.UUID("17088572-377f-44ef-8f4e-b09fff46a070")
FFS_ATTRIB_CHECKSUM = 0x40
FFS_FIXED_CHECKSUM = 0xAA
FFS_HDR = 24
FFS_PAD, FFS_RAW = 0xF0, 0x01
SEC_COMPRESSION, SEC_FV_IMAGE = 0x01, 0x17
IVB_MODEL = 0x3A  # 3rd gen Core (Ivy Bridge): CPUID 0x306Ax
SNB_MODEL = 0x2A  # 2nd gen Core (Sandy Bridge): CPUID 0x206Ax


class ToolError(Exception):
    pass


# --------------------------------------------------------------------------- microcode
class Ucode:
    def __init__(self, buf, off):
        (self.hdr, self.rev, self.date, self.sig, self.csum, self.ldr, self.pf,
         self.dsz, self.tsz) = struct.unpack_from("<9I", buf, off)
        if self.tsz == 0:
            self.tsz = 2048
        self.off = off

    @property
    def model(self):
        return (self.sig >> 4) & 0xF | ((self.sig >> 12) & 0xF0)

    @property
    def date_str(self):
        return "%04x-%02x-%02x" % (self.date & 0xFFFF, self.date >> 24, (self.date >> 16) & 0xFF)

    def label(self):
        return "cpuid %#07x pf %#04x rev %#04x %s size %#x" % (
            self.sig, self.pf, self.rev, self.date_str, self.tsz)


def parse_ucodes(buf, strict=True):
    """Parse sequential microcode patches; 0xFF padding is skipped on 1 KiB boundaries."""
    out, off = [], 0
    while off + 48 <= len(buf):
        if buf[off:off + 4] == b"\xff\xff\xff\xff":
            off += 0x400
            continue
        u = Ucode(buf, off)
        if u.hdr != 1 or u.ldr != 1 or u.tsz % 4 or off + u.tsz > len(buf):
            if strict:
                raise ToolError("bad microcode header at +%#x" % off)
            break
        out.append(u)
        off += u.tsz
    return out


def ucode_sum_ok(blob):
    return len(blob) % 4 == 0 and sum(struct.unpack("<%dI" % (len(blob) // 4), blob)) % (1 << 32) == 0


def intel_name(sig):
    return "%02x-%02x-%02x" % ((sig >> 8) & 0xF, ((sig >> 4) & 0xF) | ((sig >> 12) & 0xF0), sig & 0xF)


def load_candidates(directory):
    cands = []
    for name in sorted(os.listdir(directory)):
        p = os.path.join(directory, name)
        if not os.path.isfile(p):
            continue
        data = open(p, "rb").read()
        try:
            for u in parse_ucodes(data):
                blob = data[u.off:u.off + u.tsz]
                if not ucode_sum_ok(blob):
                    print("  skip %s: bad checksum" % name)
                    continue
                cands.append((u, blob, name))
        except ToolError:
            continue
    return cands


# --------------------------------------------------------------------------- FFS helpers
def sum8(b):
    return sum(b) & 0xFF


def ffs_header_ok(buf, p):
    h = bytearray(buf[p:p + FFS_HDR])
    h[17] = 0
    h[23] = 0
    return sum8(h) == 0


def ffs_file_ok(buf, p, size):
    attr = buf[p + 19]
    if attr & FFS_ATTRIB_CHECKSUM:
        return (sum8(buf[p + FFS_HDR:p + size]) + buf[p + 17]) & 0xFF == 0
    return buf[p + 17] == FFS_FIXED_CHECKSUM


def ffs_fix_file_checksum(buf, p, size):
    if buf[p + 19] & FFS_ATTRIB_CHECKSUM:
        buf[p + 17] = (-sum8(buf[p + FFS_HDR:p + size])) & 0xFF


def ffs_size(buf, p):
    return buf[p + 20] | (buf[p + 21] << 8) | (buf[p + 22] << 16)


def iter_ffs(buf, fv):
    """Yield (offset, guid, type, size) for every file of the FV that starts at `fv`."""
    if buf[fv + 0x28:fv + 0x2C] != b"_FVH":
        raise ToolError("no _FVH at %#x" % fv)
    fvlen = struct.unpack_from("<Q", buf, fv + 0x20)[0]
    hlen = struct.unpack_from("<H", buf, fv + 0x30)[0]
    end = min(len(buf), fv + fvlen)
    p = fv + ((hlen + 7) & ~7)
    while p + FFS_HDR <= end:
        size = ffs_size(buf, p)
        if size < FFS_HDR or size == 0xFFFFFF or p + size > end:
            break
        yield p, uuid.UUID(bytes_le=bytes(buf[p:p + 16])), buf[p + 18], size
        p = fv + ((p - fv + size + 7) & ~7)


def iter_sections(buf, start, end):
    p = start
    while p + 4 <= end:
        size = buf[p] | (buf[p + 1] << 8) | (buf[p + 2] << 16)
        if size < 4 or size == 0xFFFFFF or p + size > end:
            break
        yield p, buf[p + 3], size
        p = (p + size + 3) & ~3


def find_fvs(buf):
    """Top level firmware volumes: every _FVH on a 4 KiB boundary."""
    return [o - 0x28 for o in range(0x28, len(buf) - 4, 0x1000) if buf[o:o + 4] == b"_FVH"]


# --------------------------------------------------------------------------- LZMA (EDK2 style)
def lzma_unpack(comp):
    props, dictsz, usize = struct.unpack_from("<BIQ", comp, 0)
    d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    out = d.decompress(comp)
    if len(out) != usize:
        raise ToolError("LZMA size mismatch")
    return out


def lzma_pack(data, like, limit):
    """Recompress `data` with the same props/dictionary as header `like`, fitting in `limit` bytes."""
    props, dictsz, _ = struct.unpack_from("<BIQ", like, 0)
    lc, lp, pb = props % 9, (props // 9) % 5, props // 45
    best = None
    for nice in (273, 128, 64, 32):
        for mf in (lzma.MF_BT4, lzma.MF_BT2, lzma.MF_BT3):
            for preset in (9 | lzma.PRESET_EXTREME, 9):
                flt = [{"id": lzma.FILTER_LZMA1, "preset": preset, "dict_size": dictsz, "lc": lc,
                        "lp": lp, "pb": pb, "nice_len": nice, "mf": mf, "mode": lzma.MODE_NORMAL}]
                raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=flt)
                if best is None or len(raw) < len(best):
                    best = raw
    blob = struct.pack("<BIQ", props, dictsz, len(data)) + best
    if len(blob) > limit:
        raise ToolError("recompressed section is %d bytes, slot only holds %d" % (len(blob), limit))
    if lzma_unpack(blob) != data:
        raise ToolError("LZMA round trip failed")
    return blob + b"\xff" * (limit - len(blob))


# --------------------------------------------------------------------------- walking + patching
class Report:
    def __init__(self):
        self.lines = []
        self.copies = []   # list of (path, [Ucode], bytes)
        self.changes = []  # human readable
        self.skipped = []

    def log(self, msg, depth=0):
        self.lines.append("  " * depth + msg)


def walk(buf, fv, path, rep, patcher=None, depth=0):
    """Walk one FV. If `patcher` is set, modify microcode bodies in place. Returns True if changed."""
    changed = False
    for p, guid, typ, size in iter_ffs(buf, fv):
        loc = "%s/%#x" % (path, p)
        if guid == GUID_UCODE and typ == FFS_RAW:
            body = bytes(buf[p + FFS_HDR:p + size])
            ucs = parse_ucodes(body)
            rep.copies.append((loc, ucs, body))
            rep.log("microcode FFS %s: %d patches, %#x bytes" % (loc, len(ucs), len(body)), depth)
            if patcher:
                new = patcher(loc, bytearray(body), ucs)
                if new is not None and bytes(new) != body:
                    buf[p + FFS_HDR:p + size] = new
                    ffs_fix_file_checksum(buf, p, size)
                    changed = True
            continue
        if typ == FFS_PAD:
            continue
        for sp, st, ss in iter_sections(buf, p + FFS_HDR, p + size):
            if st == SEC_FV_IMAGE:
                changed |= walk(buf, sp + 4, loc, rep, patcher, depth + 1)
            elif st == SEC_COMPRESSION:
                ulen, ctype = struct.unpack_from("<IB", buf, sp + 4)
                if ctype == 0:
                    continue
                if ctype != 2:
                    rep.log("skip %s: unsupported compression type %d" % (loc, ctype), depth)
                    continue
                comp = bytes(buf[sp + 9:sp + ss])
                inner = bytearray(lzma_unpack(comp))
                sub = False
                for ip, it, isz in iter_sections(inner, 0, len(inner)):
                    if it == SEC_FV_IMAGE:
                        sub |= walk(inner, ip + 4, loc + "[lzma]", rep, patcher, depth + 1)
                if sub:
                    buf[sp + 9:sp + ss] = lzma_pack(bytes(inner), comp, ss - 9)
                    ffs_fix_file_checksum(buf, p, size)
                    changed = True
    return changed


def walk_image(buf, rep, patcher=None):
    changed = False
    for fv in find_fvs(buf):
        rep.log("FV @ %#x" % fv)
        changed |= walk(buf, fv, "FV%#x" % fv, rep, patcher, 1)
    return changed


def check_all_ffs(buf):
    """Return (total, bad) FFS file counts, recursing into compressed volumes."""
    tot = bad = 0

    def rec(b, fv):
        nonlocal tot, bad
        for p, guid, typ, size in iter_ffs(b, fv):
            tot += 1
            if not (ffs_header_ok(b, p) and ffs_file_ok(b, p, size)):
                bad += 1
            if typ == FFS_PAD:
                continue
            for sp, st, ss in iter_sections(b, p + FFS_HDR, p + size):
                if st == SEC_FV_IMAGE:
                    rec(b, sp + 4)
                elif st == SEC_COMPRESSION and b[sp + 8] == 2:
                    inner = bytearray(lzma_unpack(bytes(b[sp + 9:sp + ss])))
                    for ip, it, isz in iter_sections(inner, 0, len(inner)):
                        if it == SEC_FV_IMAGE:
                            rec(inner, ip + 4)

    for fv in find_fvs(buf):
        rec(buf, fv)
    return tot, bad


# --------------------------------------------------------------------------- commands
def cmd_audit(buf, out=print):
    rep = Report()
    walk_image(buf, rep)
    for l in rep.lines:
        out(l)
    out("")
    models = {}
    for loc, ucs, body in rep.copies:
        out("copy %s" % loc)
        for u in ucs:
            out("   +%#06x %s" % (u.off, u.label()))
            models.setdefault(u.model, set()).add(u.sig)
    if len(rep.copies) > 1:
        same = all(c[2] == rep.copies[0][2] for c in rep.copies)
        out("\nall microcode copies identical: %s" % same)
    ivb = sorted(s for s in models.get(IVB_MODEL, ()))
    snb = sorted(s for s in models.get(SNB_MODEL, ()))
    out("2nd gen (Sandy Bridge) CPUIDs present: %s" % (", ".join("%#x" % s for s in snb) or "none"))
    out("3rd gen (Ivy Bridge)   CPUIDs present: %s" % (", ".join("%#x" % s for s in ivb) or "none"))
    tot, bad = check_all_ffs(buf)
    out("FFS files checked: %d, bad checksum: %d" % (tot, bad))
    return rep


ES_DROP_ORDER = (0x306A2, 0x306A4, 0x306A5, 0x306A6, 0x306A8)  # pre-production Ivy Bridge steppings


def cmd_patch(buf, ucode_dir, models, allow_downgrade=False, drop_es=False):
    cands = load_candidates(ucode_dir)
    print("candidate microcode patches loaded: %d" % len(cands))
    rep = Report()

    def patcher(loc, body, ucs):
        cap = len(body)

        def plan(grow):
            ents, msgs, skipped = [], [], []
            for u in ucs:
                blob, cur, repl = bytes(body[u.off:u.off + u.tsz]), u, None
                if u.model in models:
                    best = None
                    for c, cb, name in cands:
                        if c.sig == u.sig and c.pf == u.pf and (c.rev > u.rev or allow_downgrade):
                            if best is None or c.rev > best[0].rev:
                                best = (c, cb, name)
                    if not best:
                        skipped.append("%s %s: no newer patch available (%s)" % (loc, u.label(), intel_name(u.sig)))
                    elif best[0].tsz % 0x400 or (best[0].tsz != u.tsz and not grow):
                        skipped.append("%s %s: new patch %s is %#x bytes, slot is %#x - skipped"
                                       % (loc, u.label(), best[2], best[0].tsz, u.tsz))
                    else:
                        cur, blob, repl = best[0], best[1], best[2]
                        msgs.append("%s cpuid %#x: rev %#x (%s) -> rev %#x (%s) from %s"
                                    % (loc, u.sig, u.rev, u.date_str, cur.rev, cur.date_str, repl))
                ents.append([u, cur, blob, repl is not None])
            return ents, msgs, skipped

        ents, msgs, skipped = plan(True)
        dropped = []
        if sum(len(e[2]) for e in ents) > cap and drop_es:
            for sig in ES_DROP_ORDER:
                if sum(len(e[2]) for e in ents) <= cap:
                    break
                victims = [e for e in ents if e[0].sig == sig and not e[3]]
                for e in victims:
                    ents.remove(e)
                    dropped.append("%s dropped engineering-sample patch %s" % (loc, e[0].label()))
        if sum(len(e[2]) for e in ents) > cap:
            ents, msgs, skipped = plan(False)  # fall back to same-size replacements only
            dropped = []
            if any("slot is" in x for x in skipped):
                skipped.append("%s: not enough room for larger patches (use --drop-engineering-samples)" % loc)
        rep.changes += msgs + dropped
        rep.skipped += skipped
        out = b"".join(e[2] for e in ents)
        return bytearray(out + b"\xff" * (cap - len(out)))

    changed = walk_image(buf, rep, patcher)
    for c in rep.changes:
        print("PATCHED  " + c)
    for s in rep.skipped:
        print("SKIPPED  " + s)
    if not changed:
        print("nothing to change")
    return changed


def cmd_verify(orig, new):
    errors = []
    if len(orig) != len(new):
        errors.append("image size changed")
    ro, rn = Report(), Report()
    walk_image(bytearray(orig), ro)
    walk_image(bytearray(new), rn)
    if len(ro.copies) != len(rn.copies):
        errors.append("number of microcode copies changed")
    for (lo, uo, bo), (ln, un, bn) in zip(ro.copies, rn.copies):
        so = {(u.sig, u.pf): u for u in uo}
        sn = {(u.sig, u.pf): u for u in un}
        if not set(sn) <= set(so):
            errors.append("new CPUIDs appeared in " + ln)
        for k in set(so) - set(sn):
            if k[0] not in ES_DROP_ORDER:
                errors.append("non engineering-sample patch %#x was removed in %s" % (k[0], ln))
        if 0x306A9 in {k[0] for k in so} and 0x306A9 not in {k[0] for k in sn}:
            errors.append("306A9 missing after patch in " + ln)
        for u in un:
            if not ucode_sum_ok(bn[u.off:u.off + u.tsz]):
                errors.append("bad microcode checksum %#x in %s" % (u.sig, ln))
            if (u.sig, u.pf) in so and u.rev < so[(u.sig, u.pf)].rev:
                errors.append("revision went backwards for %#x" % u.sig)
        if len(bn) != len(bo):
            errors.append("microcode FFS body size changed in " + ln)
    if len({c[2] for c in rn.copies}) > 1:
        errors.append("microcode copies differ from each other")
    t0, b0 = check_all_ffs(bytearray(orig))
    t1, b1 = check_all_ffs(bytearray(new))
    print("FFS files: %d -> %d, bad checksums: %d -> %d" % (t0, t1, b0, b1))
    if t0 != t1:
        errors.append("FFS file count changed")
    if b1 > b0:
        errors.append("new bad FFS checksums introduced")
    # everything outside the BIOS region must be byte identical
    diff = [i for i in range(0, len(orig), 0x1000) if orig[i:i + 0x1000] != new[i:i + 0x1000]]
    if diff:
        print("changed 4K blocks: %d (first %#x, last %#x)" % (len(diff), diff[0], diff[-1]))
        if diff[0] < 0x180000:
            errors.append("bytes changed outside the BIOS region (before 0x180000)")
    for e in errors:
        print("ERROR  " + e)
    print("VERIFY " + ("FAILED" if errors else "OK"))
    return not errors


def cmd_selftest(buf):
    rep = Report()
    walk_image(buf, rep)
    target = None
    for loc, ucs, body in rep.copies:
        for u in ucs:
            if u.sig == 0x306A9:
                target = (u, body[u.off:u.off + u.tsz])
        break
    if not target:
        raise ToolError("selftest needs a 306A9 patch in the image")
    u, blob = target
    fake = bytearray(blob)
    struct.pack_into("<I", fake, 4, u.rev + 8)
    struct.pack_into("<I", fake, 16, 0)  # checksum field is dword 4
    struct.pack_into("<I", fake, 16, (-sum(struct.unpack("<%dI" % (len(fake) // 4), bytes(fake)))) % (1 << 32))
    assert ucode_sum_ok(bytes(fake))
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "06-3a-09"), "wb").write(fake)
        new = bytearray(buf)
        if not cmd_patch(new, td, {IVB_MODEL}):
            raise ToolError("selftest: patch not applied")
        if not cmd_verify(bytes(buf), bytes(new)):
            raise ToolError("selftest: verify failed")
        rep2 = Report()
        walk_image(bytearray(new), rep2)
        for loc, ucs, body in rep2.copies:
            r = [x.rev for x in ucs if x.sig == 0x306A9][0]
            assert r == u.rev + 8, "revision not updated in " + loc
    # scenario 2: a larger (+0x800) patch; the table is repacked into the free tail of the FFS
    big = bytearray(blob) + bytearray(range(256)) * 8
    struct.pack_into("<I", big, 4, u.rev + 8)
    struct.pack_into("<I", big, 28, len(big) - 48)
    struct.pack_into("<I", big, 32, len(big))
    struct.pack_into("<I", big, 16, 0)
    struct.pack_into("<I", big, 16, (-sum(struct.unpack("<%dI" % (len(big) // 4), bytes(big)))) % (1 << 32))
    assert ucode_sum_ok(bytes(big)) and len(big) == u.tsz + 0x800
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "06-3a-09"), "wb").write(big)
        new = bytearray(buf)
        if not cmd_patch(new, td, {IVB_MODEL}):
            raise ToolError("selftest: larger patch not applied")
        if not cmd_verify(bytes(buf), bytes(new)):
            raise ToolError("selftest: verify failed (larger patch)")
        rep3 = Report()
        walk_image(bytearray(new), rep3)
        for loc, ucs, body in rep3.copies:
            got = {x.sig: x for x in ucs}
            assert got[0x306A9].rev == u.rev + 8 and got[0x306A9].tsz == len(big), loc
            assert len(got) == 8, "no patch may be lost: " + loc
    print("SELFTEST OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit"); a.add_argument("image")
    p = sub.add_parser("patch"); p.add_argument("image"); p.add_argument("--ucode-dir", required=True)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--models", default="3a", help="comma separated CPU models (hex). 3a=Ivy Bridge, 2a=Sandy Bridge")
    p.add_argument("--drop-engineering-samples", action="store_true",
                   help="free room for larger patches by removing pre-production Ivy Bridge patches (306A2...)")
    v = sub.add_parser("verify"); v.add_argument("original"); v.add_argument("patched")
    s = sub.add_parser("selftest"); s.add_argument("image")
    args = ap.parse_args()
    try:
        if args.cmd == "audit":
            cmd_audit(bytearray(open(args.image, "rb").read()))
        elif args.cmd == "patch":
            orig = open(args.image, "rb").read()
            buf = bytearray(orig)
            models = {int(x, 16) for x in args.models.split(",")}
            changed = cmd_patch(buf, args.ucode_dir, models, drop_es=args.drop_engineering_samples)
            open(args.output, "wb").write(buf)
            print("sha256 %s  %s" % (hashlib.sha256(buf).hexdigest(), args.output))
            if changed and not cmd_verify(orig, bytes(buf)):
                return 2
        elif args.cmd == "verify":
            return 0 if cmd_verify(open(args.original, "rb").read(), open(args.patched, "rb").read()) else 2
        elif args.cmd == "selftest":
            cmd_selftest(bytearray(open(args.image, "rb").read()))
    except ToolError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
