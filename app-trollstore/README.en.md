# IOSDecryptHub TrollStore Manager

<div align="right">
  <a href="./README.md">中文</a> | <b>English</b>
</div>

> **Non-jailbreak solution** — installed via TrollStore, it injects the dylib by directly patching the target app's Mach-O binary.
> Based on the open-source [TrollFools](https://github.com/Lessica/TrollFools) approach.

## User Flow

```
1. Install IOSDecryptHubTS.ipa via TrollStore
2. Open the app → see the list of installed apps
3. Toggle a target app ON → dylib injection complete (relaunch the target app to take effect)
4. Toggle OFF → restore the original binary
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│              IOSDecryptHubTS.app                 │
│              (installed via TrollStore)          │
├─────────────────────────────────────────────────┤
│                                                 │
│  App.swift (SwiftUI)                            │
│    └─ AppListViewModel                          │
│         └─ DHInjector (ObjC)                    │
│              ├─ macho_patch.c (pure C)          │
│              │   ├─ Insert LC_LOAD_DYLIB        │
│              │   ├─ Remove LC_LOAD_DYLIB        │
│              │   └─ Supports fat/thin binaries  │
│              ├─ LSApplicationWorkspace (private)│
│              │   └─ Enumerate installed apps    │
│              ├─ ldid (pseudo-signing)           │
│              ├─ ct_bypass (CoreTrust bypass)    │
│              └─ chown (change owner to installd)│
│                                                 │
│  Embedded resources:                            │
│    decrypt_helper.dylib  (hook engine)          │
│    ct_bypass             (signing tool)         │
│    ldid                  (signing tool)         │
└─────────────────────────────────────────────────┘
```

## Injection Flow

```
Inject (Toggle ON):
  1. Kill the target app
  2. Back up the main binary → <binary>.dh.bak
  3. Copy decrypt_helper.dylib → into the target .app/ directory
  4. macho_patch: insert LC_LOAD_DYLIB (@executable_path/decrypt_helper.dylib)
  5. ldid -S (pseudo-sign)
  6. ct_bypass -r -i <binary> -t <teamId> (CoreTrust bypass)
  7. chown 33:33 (installd ownership)

Uninstall (Toggle OFF):
  1. Kill the target app
  2. Restore the backup (or macho_patch removes LC_LOAD_DYLIB)
  3. Delete the dylib
  4. Re-sign + chown
```

## Build

```bash
# One-command IPA build
make ipa

# Or manually
./app-trollstore/build_ipa.sh
```

Artifact: `build/trollstore/IOSDecryptHubTS_<version>.ipa`

## File Overview

| File | Description |
|------|-------------|
| `IOSDecryptHubTS/macho_patch.h/c` | Mach-O LC_LOAD_DYLIB insert/remove (pure C, fat-binary support) |
| `IOSDecryptHubTS/DHInjector.h/m` | ObjC injection engine (app enumeration + inject/uninstall orchestration) |
| `IOSDecryptHubTS/LSApplicationWorkspace.h` | Private API declarations (enumerate installed apps) |
| `IOSDecryptHubTS/App.swift` | SwiftUI interface (app list + toggles) |
| `IOSDecryptHubTS/BridgingHeader.h` | Swift ↔ ObjC bridging |
| `IOSDecryptHubTS/Info.plist` | App configuration |
| `IOSDecryptHubTS/entitlements.plist` | TrollStore entitlements (sandbox bypass, etc.) |
| `tools/` | Signing tools directory (ct_bypass, ldid) |
| `build_ipa.sh` | Build script |

## ⚠️ Boundary Rules

- **Must not** reference any daemon / dh_server code or interfaces
- **Must not** read/write plist preference files for gating
- **Must not** depend on /var/jb or any jailbreak paths
- **Must not** use Substrate / ElleKit APIs
- **Must not** package any jailbreak deb components into the IPA

See `docs/ARCHITECTURE_BOUNDARY.md` for details.
