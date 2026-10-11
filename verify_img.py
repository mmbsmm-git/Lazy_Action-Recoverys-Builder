#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recovery.img 出厂前硬校验（CI 最后一步，不通过就让构建失败）。
用法: python3 verify_img.py <recovery.img>

校验项（任何一项不满足 -> exit 1）：
  - bootimg 头与原厂 recovery.bin 同构: tags_addr=0x54000000, header_version=1,
    second_addr=0x40f00000, page=2048, cmdline=bootopt=64S3,32N2,64N2 buildvariant=userdebug
  - 内核 blob 尾部带 MTK 追加 DTB（FDT magic d00dfeed，距尾 110572B）—— lk 唯一 DTB 来源
  - ramdisk 压缩后 <= 16MB（MTK lk 硬限制）
  - recovery_dtbo 段存在且 100170B（magic d7b7ab1e）
  - ramdisk 内含关键条目: twres/ui.xml(主题入口)、twres/splash.xml、ueventd.rc、
    sbin/recovery、init、etc/twrp.fstab、prop.default
  - 镜像总大小 <= 32MB
"""
import struct, zlib, sys, os

FDT = b'\xd0\x0d\xfe\xed'
EXP_CMDLINE = 'bootopt=64S3,32N2,64N2 buildvariant=userdebug'
CRITICAL = ['twres/ui.xml', 'twres/splash.xml', 'ueventd.rc', 'sbin/recovery',
            'init', 'etc/twrp.fstab', 'prop.default']
fails = []

def ok(cond, msg):
    print('  [%s] %s' % ('OK' if cond else 'FAIL', msg))
    if not cond:
        fails.append(msg)


def load_cpio(d, ks, rs):
    """见 slim_rec.py：ramdisk 可能页对齐存放，两种偏移都试，要求完整解压。"""
    best = None
    for start in {0x800 + ks, (0x800 + ks + 2047) & ~2047}:
        seg = d[start:start + rs]
        g = seg.find(b'\x1f\x8b')
        if g < 0:
            continue
        try:
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = obj.decompress(seg[g:])
            try:
                out += obj.flush()
            except Exception:
                pass
        except Exception:
            continue
        eof = bool(getattr(obj, 'eof', False))
        if best is None or (eof, len(out)) > (best[0], len(best[1])):
            best = (eof, out, start)
    if best is None:
        raise SystemExit('[FATAL] 无法定位 ramdisk gzip')
    eof, out, start = best
    print('  ramdisk @0x%x decompressed=%d eof=%s' % (start, len(out), eof))
    if not eof:
        fails.append('ramdisk gzip 不完整（读取偏移或镜像损坏）')
    return out

def main(p):
    d = open(p, 'rb').read()
    print('== verify_img: %s (%d bytes, %.2fMB) ==' % (p, len(d), len(d)/1048576))
    ok(d[:8] == b'ANDROID!', 'magic ANDROID!')
    ks, ka, rs, ra, ss, sa, ta, pg = struct.unpack('<8I', d[8:40])
    hv, osv = struct.unpack('<II', d[40:48])
    cmd = d[64:64+512].split(b'\0')[0].decode()
    ok(ta == 0x54000000, 'tags_addr == 0x54000000 (got 0x%08x)' % ta)
    ok(hv == 1, 'header_version == 1 (got %d)' % hv)
    ok(sa == 0x40f00000, 'second_addr == 0x40f00000 (got 0x%08x)' % sa)
    ok(pg == 2048, 'page_size == 2048')
    ok(ka == 0x40080000 and ra == 0x55000000, 'kernel/ramdisk addr 0x40080000/0x55000000')
    ok(cmd == EXP_CMDLINE, 'cmdline == %r' % cmd)
    ok(rs <= 0x1000000, 'ramdisk_size %d <= 16MB' % rs)
    ok(len(d) <= 33554432, 'image <= 32MB')

    kb = d[0x800:0x800+ks]
    fo = kb.rfind(FDT)
    ok(fo >= 0 and (len(kb) - fo) == 110572,
       'kernel tail DTB (FDT magic, 110572B from end)  [lk DTB source]')

    if hv >= 1:
        dsz = struct.unpack('<I', d[1632:1636])[0]
        doff = struct.unpack('<Q', d[1636:1644])[0]
        ok(dsz == 100170, 'recovery_dtbo_size == 100170 (got %d)' % dsz)
        sec = d[doff:doff+dsz]
        ok(sec[:4] == bytes.fromhex('d7b7ab1e'), 'dtbo magic d7b7ab1e')

    cpio = load_cpio(d, ks, rs)
    names = set(); pos = 0
    while pos + 110 <= len(cpio):
        h = cpio[pos:pos+110]
        if h[:6] != b'070701':
            break
        F = lambda o, n: int(h[o:o+n], 16)
        fsz = F(54, 8); ns = F(94, 8)
        nm = cpio[pos+110:pos+110+ns].rstrip(b'\0').decode('utf-8', 'replace')
        names.add(nm)
        pos = (pos+110+ns+3) & ~3
        pos = (pos+fsz+3) & ~3
        if nm == 'TRAILER!!!':
            break
    print('  ramdisk entries=%d' % len(names))
    for c in CRITICAL:
        ok(c in names, 'ramdisk 含 %s' % c)

    print('== RESULT: %s ==' % ('PASS' if not fails else 'FAIL (%d)' % len(fails)))
    if fails:
        print('   失败项:')
        for f in fails:
            print('     - %s' % f)
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    main(sys.argv[1])
