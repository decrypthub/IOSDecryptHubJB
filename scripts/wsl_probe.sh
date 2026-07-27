#!/usr/bin/env bash
# Probe the WSL environment for what we need to cross-compile an iOS dylib.
set -u
echo "=== whoami / home ==="
whoami; echo "HOME=$HOME"
echo "=== sudo ==="
if sudo -n true 2>/dev/null; then echo "passwordless sudo: YES"; else echo "passwordless sudo: NO"; fi
echo "=== tools ==="
for t in git perl make curl wget xz fakeroot rsync clang gcc cc dpkg-deb ldid; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "OK   $t -> $(command -v "$t")"
  else
    echo "MISS $t"
  fi
done
echo "=== theos ==="
if [ -n "${THEOS:-}" ]; then echo "THEOS=$THEOS"; fi
if [ -d "$HOME/theos" ]; then echo "~/theos exists"; else echo "no ~/theos"; fi
echo "=== clang version (if any) ==="
clang --version 2>/dev/null | head -1 || echo "no clang"
