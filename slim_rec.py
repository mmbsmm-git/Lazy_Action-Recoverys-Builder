#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OFRP recovery.img 精简脚本（MTK lk ramdisk <=16MB 限制）。
用法: python3 slim_rec.py <input.img> <output.img>

根因: MTK lk 忽略 ramdisk_addr 字段，固定解压到 0x55000000 起的 16MB buffer，
且硬检查 img header 的 ramdisk_size 字段必须 <= 0x1000000(16MB)。
OFRP 默认 ramdisk >16MB -> lk 死循环。本脚本删减 sbin 冗余 + 装饰字体，
把压缩后 ramdisk 降到 <=16MB，并保留完整 header(含 cmdline) + 原厂 kernel。
"""
import struct, zlib, gzip, os, sys

SBL_DEL = {
    # 无关 / f2fs-only 工具（本机 data/cache/vendor/system 全 ext4，f2fs 工具无用）
    'charger', 'sload.f2fs', 'mkfs.f2fs',
    'libclang_rt.ubsan_standalone-aarch64-android.so',
    # 非刷机冗余：截屏(fb2png)、lzma/pigz(刷zip走zlib)、调试回溯库
    'fb2png', 'lzma', 'liblzma.so', 'pigz',
    'libunwindstack.so', 'libunwind.so', 'libbacktrace.so',
    # 日志工具（logd/logcat 二进制，init 起失败不 FATAL；liblog.so 库保留）
    'logd', 'logcat', 'liblogcat.so', 'liblogwrap.so', 'libsysutils.so',
    # 外置存储(ntfs/exfat/fat)支持：P709 刷机走 internal(/data/media)+fastboot，无外置SD场景
    'libntfs-3g.so', 'libfuse-lite.so', 'exfat-fuse', 'mkfs.ntfs', 'mount.ntfs',
    'fsck.ntfs', 'mkexfatfs', 'fsck.exfat', 'libexfat_twrp.so', 'fsck.fat',
    'mkfs.fat', 'fatlabel',
    # NOTE: 保留 bash + toybox 全套命令行（OFRP 终端要能用）。
    # 保留刷机必需 zip/aapt/magiskboot/unpackbootimg/mkbootimg/e2fsck/mke2fs/resize2fs。
}
FONTS_KEEP = {'RobotoCondensed-Regular.ttf', 'DroidSansFallback.ttf', 'OFL.txt'}
LANG_KEEP = {'en.xml', 'zh_CN.xml'}   # 只留中英（用户要求 OFRP 只显示中/英）

def parse_cpio(data):
    entries = []
    pos = 0
    while True:
        if pos + 110 > len(data):
            break
        hdr = data[pos:pos+110]
        if hdr[:6] != b'070701':
            break
        def f(o, n): return int(hdr[o:o+n], 16)
        ino=f(6,8); mode=f(14,8); uid=f(22,8); gid=f(30,8); nlink=f(38,8); mtime=f(46,8)
        fsz=f(54,8); devmaj=f(62,8); devmin=f(70,8); rdmaj=f(78,8); rdmin=f(86,8)
        namesz=f(94,8); check=f(102,8)
        name = data[pos+110:pos+110+namesz].rstrip(b'\0').decode('utf-8','replace')
        ds = (pos + 110 + namesz + 3) & ~3
        content = data[ds:ds+fsz] if fsz else b''
        entries.append(dict(name=name, mode=mode, uid=uid, gid=gid, nlink=nlink,
            mtime=mtime, fsz=fsz, devmaj=devmaj, devmin=devmin, rdmaj=rdmaj,
            rdmin=rdmin, namesz=namesz, check=check, content=content))
        pos = (ds + fsz + 3) & ~3
        if name == 'TRAILER!!!':
            break
    return entries

def build_cpio(entries):
    out = b''
    for e in entries:
        name = e['name'].encode('utf-8') + b'\0'
        ns = len(name)
        hdr = b'070701' + b''.join(('%08x' % v).encode() for v in [
            e['ino'], e['mode'], e['uid'], e['gid'], e['nlink'], e['mtime'],
            e['fsz'], e['devmaj'], e['devmin'], e['rdmaj'], e['rdmin'], ns, e['check']])
        assert len(hdr) == 110, len(hdr)
        out += hdr
        out += name
        out += b'\0' * ((4 - (len(out) % 4)) % 4)
        out += e['content']
        out += b'\0' * ((4 - (len(out) % 4)) % 4)
    return out

def main(inp, outp):
    d = open(inp, 'rb').read()
    ksz, kaddr, rsz, raddr = struct.unpack('<IIII', d[8:24])
    kernel = d[0x800:0x800+ksz]
    roff = 0x800 + ksz
    rseg = d[roff:roff+rsz]
    g = rseg.find(b'\x1f\x8b')
    obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
    cpio = obj.decompress(rseg[g:])
    try: cpio += obj.flush()
    except Exception: pass
    print('input: compressed=%d decompressed=%d kernel=%d' % (rsz, len(cpio), len(kernel)))

    ents = parse_cpio(cpio)
    print('entries:', len(ents))
    for i, e in enumerate(ents): e['ino'] = i + 1
    body = [e for e in ents if e['name'] != 'TRAILER!!!']

    removed = 0
    keep = []
    for e in body:
        name = e['name']
        base = os.path.basename(name)
        if ('/sbin/' in name or name.startswith('sbin/')) and base in SBL_DEL:
            removed += e['fsz']; print('  del sbin/%s (%dKB)' % (base, e['fsz']//1024)); continue
        if ('/fonts/' in name or name.startswith('twres/fonts/')) and base not in FONTS_KEEP:
            removed += e['fsz']; print('  del fonts/%s (%dKB)' % (base, e['fsz']//1024)); continue
        if ('/languages/' in name or name.startswith('twres/languages/')) and base not in LANG_KEEP:
            removed += e['fsz']; print('  del lang/%s (%dKB)' % (base, e['fsz']//1024)); continue
        keep.append(e)
    print('removed decompressed %dKB' % (removed//1024))

    new_cpio = build_cpio(keep) + b'070701' + b'0'*104 + b'TRAILER!!!\0' + b'\0'*8
    gz = gzip.compress(new_cpio, compresslevel=9)
    print('new ramdisk compressed=%d (%.2fMB)  <=16MB: %s' % (len(gz), len(gz)/1048576, len(gz)<=0x1000000))
    assert len(gz) <= 0x1000000, 'ramdisk still >16MB!'

    outimg = bytearray(d[:0x800+ksz])   # keep full header + kernel
    outimg[16:20] = struct.pack('<I', len(gz))
    outimg[20:24] = struct.pack('<I', 0x55000000)
    outimg += gz
    open(outp, 'wb').write(bytes(outimg))
    print('OUTPUT %s total=%d (%.2fMB) kernel=%d ramdisk=%d raddr=0x55000000' % (
        outp, len(outimg), len(outimg)/1048576, len(kernel), len(gz)))

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
