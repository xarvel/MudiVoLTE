# Third-party components in mudi-imsd

`mudi-imsd` is a single statically linked binary (linux/arm64, musl libc).
Everything third-party that is linked into it is listed below; the license
texts are in `licenses/` next to this file (last column).

G.722 (the codec towards the phones) is the project's own pure-Go
implementation in `volte/media/g722`, written from ITU-T Recommendation G.722
(11/88); it carries no third-party code.

The C part of the binary consists only of `libopencore-amrwb.a`,
`libvo-amrwbenc.a`, musl's `libc.a` and start files, ten objects from GCC's
`libgcc.a` and GCC's `crtbeginS.o`/`crtendS.o` (checked with a linker map).
No glibc code is linked.

| Component | Version | License | Source | Texts |
|---|---|---|---|---|
| Go standard library and runtime | go1.26.3 | BSD-3-Clause, plus the Go patent grant (PATENTS) | https://go.googlesource.com/go (tag go1.26.3) | `licenses/go/` |
| github.com/damonto/wwan-go | v0.0.1 | MIT | https://github.com/damonto/wwan-go | `licenses/github.com/damonto/wwan-go/` |
| github.com/emiago/sipgo | v1.7.2 | BSD-2-Clause | https://github.com/emiago/sipgo | `licenses/github.com/emiago/sipgo/` |
| github.com/gobwas/httphead | v0.1.0 | MIT | https://github.com/gobwas/httphead | `licenses/github.com/gobwas/httphead/` |
| github.com/gobwas/pool | v0.2.1 | MIT | https://github.com/gobwas/pool | `licenses/github.com/gobwas/pool/` |
| github.com/gobwas/ws | v1.3.2 | MIT | https://github.com/gobwas/ws | `licenses/github.com/gobwas/ws/` |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause | https://github.com/google/uuid | `licenses/github.com/google/uuid/` |
| github.com/icholy/digest | v1.2.0 | MIT | https://github.com/icholy/digest | `licenses/github.com/icholy/digest/` |
| golang.org/x/sync | v0.24.0 | BSD-3-Clause, plus PATENTS | https://go.googlesource.com/sync | `licenses/golang.org/x/sync/` |
| golang.org/x/sys | v0.49.0 | BSD-3-Clause, plus PATENTS | https://go.googlesource.com/sys | `licenses/golang.org/x/sys/` |
| github.com/vishvananda/netlink | v1.3.1 | Apache-2.0 | https://github.com/vishvananda/netlink | `licenses/github.com/vishvananda/netlink/` |
| github.com/vishvananda/netns | v0.0.5 | Apache-2.0 | https://github.com/vishvananda/netns | `licenses/github.com/vishvananda/netns/` |
| rsc.io/qr | v0.2.0 | BSD-3-Clause (The Go Authors) | https://github.com/rsc/qr (tag v0.2.0) | `licenses/rsc.io/qr/` |
| opencore-amr: libopencore-amrwb (AMR-WB decoder) | 0.1.6 (Debian 0.1.6-1) | Apache-2.0 with NOTICE | http://deb.debian.org/debian/pool/main/o/opencore-amr/opencore-amr_0.1.6.orig.tar.gz (project: https://sourceforge.net/projects/opencore-amr/) | `licenses/opencore-amr/` |
| vo-amrwbenc (AMR-WB encoder) | 0.1.3 (Debian 0.1.3-2) | Apache-2.0 with NOTICE (VisualOn, Android Open Source Project; the NOTICE also carries the Unicode license) | http://deb.debian.org/debian/pool/main/v/vo-amrwbenc/vo-amrwbenc_0.1.3.orig.tar.gz (project: https://sourceforge.net/projects/opencore-amr/) | `licenses/vo-amrwbenc/` |
| musl libc | 1.2.5 (Debian 1.2.5-3.1~deb13u1) | MIT (COPYRIGHT lists authors and per-file notices) | http://deb.debian.org/debian/pool/main/m/musl/musl_1.2.5.orig.tar.gz (project: https://musl.libc.org/) | `licenses/musl/` |
| GCC libgcc.a soft-fp: addtf3, subtf3, multf3, eqtf2, extenddftf2, fixtfsi, fixunstfsi, floatsitf, floatunsitf (128-bit long double used by musl's printf) | 14.2.0 (Debian 14.2.0-19) | LGPL-2.1-or-later with a special exception: the compiled files may be linked into any program and distributed without LGPL restrictions | http://deb.debian.org/debian/pool/main/g/gcc-14/gcc-14_14.2.0.orig.tar.gz, `libgcc/soft-fp/` | `licenses/gcc/soft-fp.NOTICE` |
| GCC libgcc.a (sfp-exceptions), crtbeginS.o, crtendS.o | 14.2.0 (Debian 14.2.0-19) | GPL-3.0-or-later WITH GCC-exception-3.1 | same tarball, `libgcc/` | `licenses/gcc/COPYING3`, `licenses/gcc/COPYING.RUNTIME` |

The AMR-WB codec sources ship a patent disclaimer ("THIS IS NOT A GRANT OF
PATENT RIGHTS"), included as `patent_disclaimer.txt` in both codec
directories.
