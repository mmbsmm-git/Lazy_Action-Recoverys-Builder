#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OFRP recovery.img 后处理（MTK lk 限制 + 原厂头结构对齐）。
用法: python3 slim_rec.py <input.img> <output.img> [recovery_dtbo.img]

作用：
 1) ramdisk 精简到 <=16MB（MTK lk 硬限制）。
 2) 用「原厂 recovery.bin 完全一致」的 bootimg v1 头重写镜像头：
      kernel_addr=0x40080000 ramdisk_addr=0x55000000 tags_addr=0x54000000
      second_addr=0x40f00000 page=2048 header_version=1 os_version=0x1200013a
    —— 编译系统会写出 tags_addr=0x40078100 / header_version=0（错），
       而 lk 把 tags_addr 直接传给 boot_linux 当 DTB 目的地址（mt_boot.c:1335）。
 3) 校验内核 blob 尾部带 MTK 追加 DTB（FDT magic d00dfeed，原厂 110572B）。
    lk 在 boot_linux_fdt() 里从内核镜像尾部反向扫描 FDT magic；找不到会
    dtb_addr=0 解引用空指针 -> 崩溃 -> 看门狗重启 -> 「有/无背光反复循环」。
    这是所有自编 OFRP/TWRP 死循环的根因，必须保留。
 4) 追加 recovery_dtbo 段（原厂 100170B，v1 头字段引用）。
"""
import struct, zlib, gzip, os, sys

SBL_DEL = {
    'charger', 'sload.f2fs', 'mkfs.f2fs',
    'libclang_rt.ubsan_standalone-aarch64-android.so',
    'fb2png', 'lzma', 'liblzma.so', 'pigz',
    'libunwindstack.so', 'libunwind.so', 'libbacktrace.so',
    'logd', 'logcat', 'liblogcat.so', 'libsysutils.so',
    # liblogwrap.so 必须保留（libext4_utils.so 依赖它）
    'libntfs-3g.so', 'libfuse-lite.so', 'exfat-fuse', 'mkfs.ntfs', 'mount.ntfs',
    'fsck.ntfs', 'mkexfatfs', 'fsck.exfat', 'libexfat_twrp.so', 'fsck.fat',
    'mkfs.fat', 'fatlabel',
    # 保留 bash + toybox 全套 + 刷机工具
}
FONTS_KEEP = {'RobotoCondensed-Regular.ttf', 'DroidSansFallback.ttf', 'OFL.txt'}
LANG_KEEP = {'en.xml', 'zh_CN.xml'}

# —— 原厂 recovery.bin (md5 ae5fd316..., 能进 rec) 的头常量 ——
PAGE = 2048
KERNEL_ADDR = 0x40080000
RAMDISK_ADDR = 0x55000000
TAGS_ADDR = 0x54000000
SECOND_ADDR = 0x40f00000
OS_VERSION = 0x1200013a
HEADER_VERSION = 1
CMDLINE = b'bootopt=64S3,32N2,64N2 buildvariant=userdebug'
FDT_MAGIC = b'\xd0\x0d\xfe\xed'


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
        fsz = f(54, 8); namesz = f(94, 8)
        name = data[pos+110:pos+110+namesz].rstrip(b'\0').decode('utf-8', 'replace')
        ds = (pos + 110 + namesz + 3) & ~3
        content = data[ds:ds+fsz] if fsz else b''
        entries.append(dict(name=name, ino=f(6,8), mode=f(14,8), uid=f(22,8), gid=f(30,8),
            nlink=f(38,8), mtime=f(46,8), fsz=fsz, devmaj=f(62,8), devmin=f(70,8),
            rdmaj=f(78,8), rdmin=f(86,8), namesz=namesz, check=f(102,8), content=content))
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


def align(n, a):
    return (n + a - 1) & ~(a - 1)


def build_factory_header(kernel_size, ramdisk_size, dtbo_size, dtbo_offset):
    """构造与原厂 recovery.bin 完全同构的 bootimg v1 头（2048B 页）。"""
    h = bytearray(PAGE)
    h[0:8] = b'ANDROID!'
    struct.pack_into('<I', h, 8, kernel_size)
    struct.pack_into('<I', h, 12, KERNEL_ADDR)
    struct.pack_into('<I', h, 16, ramdisk_size)
    struct.pack_into('<I', h, 20, RAMDISK_ADDR)
    struct.pack_into('<I', h, 24, 0)          # second_size
    struct.pack_into('<I', h, 28, SECOND_ADDR)
    struct.pack_into('<I', h, 32, TAGS_ADDR)  # <<< 关键修复
    struct.pack_into('<I', h, 36, PAGE)
    struct.pack_into('<I', h, 40, HEADER_VERSION)  # <<< 关键修复
    struct.pack_into('<I', h, 44, OS_VERSION)
    # name[16] @48 = 0
    h[64:64+len(CMDLINE)] = CMDLINE
    # id[32] @576 = 0 (lk 不校验)
    # extra_cmdline[1024] @608 = 0
    struct.pack_into('<I', h, 1632, dtbo_size)
    struct.pack_into('<Q', h, 1636, dtbo_offset)
    struct.pack_into('<I', h, 1644, 1648)     # header_size (原厂值)
    return bytes(h)


def verify_dtb_in_kernel(kernel, tag=''):
    """lk 的行为：从内核尾部反向找 FDT magic，dtb_size = 距尾距离。"""
    off = kernel.rfind(FDT_MAGIC)
    if off < 0:
        raise SystemExit(
            "[FATAL] %skernel blob 不含 MTK 追加 DTB (FDT magic d00dfeed)!\n"
            "        lk 会在 boot_linux_fdt() 里 dtb_addr=0 崩溃 -> 死循环。\n"
            "        修复：把原厂内核尾部 110572B DTB 追加到 kernel blob 末尾"
            " (见 prebuilt/kernel_dtb)。" % tag)
    size_from_end = len(kernel) - off
    total = struct.unpack('>I', kernel[off+4:off+8])[0]
    print('  kernel DTB: off=0x%x size_from_end=%d totalsize=%d %s' % (
        off, size_from_end, total, 'OK' if total == size_from_end else 'MISMATCH!'))
    if total != size_from_end:
        raise SystemExit('[FATAL] DTB totalsize(%d) != distance from end(%d)' % (total, size_from_end))
    return off


def main(inp, outp, dtbo_path=None):
    d = open(inp, 'rb').read()
    ksz, kaddr, rsz, raddr = struct.unpack('<IIII', d[8:24])
    hdr_ver = struct.unpack('<I', d[40:44])[0]
    kernel = d[PAGE:PAGE+ksz]
    roff = PAGE + ksz
    rseg = d[roff:roff+rsz]
    print('input: %d bytes  hdr_ver=%d kernel=%d ramdisk=%d' % (len(d), hdr_ver, ksz, rsz))

    print('== [1] 校验内核尾部 DTB ==')
    verify_dtb_in_kernel(kernel)

    g = rseg.find(b'\x1f\x8b')
    obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
    cpio = obj.decompress(rseg[g:])
    try:
        cpio += obj.flush()
    except Exception:
        pass
    print('== [2] ramdisk: compressed=%d decompressed=%d (%.2fMB)' % (rsz, len(cpio), len(cpio)/1048576))

    ents = parse_cpio(cpio)
    for i, e in enumerate(ents):
        e['ino'] = i + 1
    body = [e for e in ents if e['name'] != 'TRAILER!!!']
    removed = 0
    keep = []
    for e in body:
        name = e['name']
        base = os.path.basename(name)
        if ('/sbin/' in name or name.startswith('sbin/')) and base in SBL_DEL:
            removed += e['fsz']; continue
        if ('/fonts/' in name or name.startswith('twres/fonts/')) and base not in FONTS_KEEP:
            removed += e['fsz']; continue
        if ('/languages/' in name or name.startswith('twres/languages/')) and base not in LANG_KEEP:
            removed += e['fsz']; continue
        if base == 'init.recovery.hlthchrg.rc':
            e['content'] = b'# charger service disabled by slim_rec.py\n'
            e['fsz'] = len(e['content'])
        keep.append(e)
    print('  removed decompressed %dKB, kept %d entries' % (removed//1024, len(keep)))

    new_cpio = build_cpio(keep) + b'070701' + b'0'*104 + b'TRAILER!!!\0' + b'\0'*8
    gz = gzip.compress(new_cpio, compresslevel=9)
    print('  new ramdisk compressed=%d (%.2fMB)  <=16MB: %s' % (len(gz), len(gz)/1048576, len(gz) <= 0x1000000))
    if len(gz) > 0x1000000:
        raise SystemExit('[FATAL] ramdisk still >16MB (MTK lk hard limit)')

    print('== [3] recovery_dtbo 段 ==')
    if dtbo_path is None:
        cand = os.path.join(os.path.dirname(os.path.abspath(inp)), 'recovery_dtbo.img')
        dtbo_path = cand if os.path.exists(cand) else None
    dtbo = b''
    if dtbo_path and os.path.exists(dtbo_path):
        dtbo = open(dtbo_path, 'rb').read()
        print('  dtbo=%d bytes (%s)' % (len(dtbo), dtbo_path))
    else:
        print('  WARNING: 未找到 recovery_dtbo（lk 不读该段，仅结构保真）')

    print('== [4] 重建原厂结构 v1 镜像 ==')
    koff = align(PAGE, PAGE)
    r_off = align(koff + len(kernel), PAGE)
    dtbo_off = align(r_off + len(gz), PAGE)
    header = build_factory_header(len(kernel), len(gz), len(dtbo), dtbo_off)
    out = bytearray()
    out += header
    out += b'\0' * (koff - len(out))
    out += kernel
    out += b'\0' * (r_off - len(out))
    out += gz
    out += b'\0' * (dtbo_off - len(out))
    out += dtbo
    out += b'\0' * ((PAGE - (len(out) % PAGE)) % PAGE)

    print('  header: tags_addr=0x%08x hdr_ver=%d kernel_addr=0x%08x ramdisk_addr=0x%08x' % (
        TAGS_ADDR, HEADER_VERSION, KERNEL_ADDR, RAMDISK_ADDR))
    print('  layout: kernel@0x%x(%d) ramdisk@0x%x(%d) dtbo@0x%x(%d)' % (
        koff, len(kernel), r_off, len(gz), dtbo_off, len(dtbo)))
    print('  total=%d (%.2fMB) <=32MB: %s' % (len(out), len(out)/1048576, len(out) <= 33554432))
    if len(out) > 33554432:
        raise SystemExit('[FATAL] image > 32MB boot partition')
    open(outp, 'wb').write(bytes(out))
    print('OUTPUT %s' % outp)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
