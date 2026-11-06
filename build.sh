#!/usr/bin/env bash
# Cross-compiles dnsping.exe (x64, no CRT). Needs mingw-w64 from nixpkgs.
set -euo pipefail
cd "$(dirname "$0")"
MINGW=$(nix build --no-link --print-out-paths nixpkgs#pkgsCross.mingwW64.buildPackages.gcc | grep -v -- -man$ | head -1)
export PATH=$MINGW/bin:$PATH
P=x86_64-w64-mingw32-
python3 mkicon.py >/dev/null
${P}windres -O coff app.rc -o app.res.o
${P}gcc -std=c99 -Os -s -ffreestanding -fno-builtin -fno-tree-loop-distribute-patterns \
  -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector -mno-stack-arg-probe \
  -ffunction-sections -Wall -Wno-missing-braces \
  -nostdlib -e entry -Wl,--subsystem,windows:6.0 -Wl,--gc-sections -Wl,--build-id=none \
  -Wl,--no-insert-timestamp -Wl,--disable-reloc-section -Wl,--exclude-all-symbols -Wl,--file-alignment,512 -Wl,--section-alignment,4096 \
  dnsping.c app.res.o -o dnsping.exe \
  -lkernel32 -luser32 -lgdi32 -lcomctl32 -lcomdlg32 -lshell32 -lws2_32 -lwinmm -liphlpapi
rm -f app.res.o
ls -l dnsping.exe
