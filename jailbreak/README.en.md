# IOSDecryptHub Jailbreak Injection Package

<div align="right">
  <a href="./README.md">中文</a> | <b>English</b>
</div>

> Injects the main dylib into target apps via jailbreak frameworks (Substrate / ElleKit / libhooker).
> Supports rootless / roothide / rootful jailbreaks.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Substrate / ElleKit / libhooker                            │
│  Loads IOSDecryptHubLoader.dylib into UIKit apps            │
└──────────────────────────┬──────────────────────────────────┘
                           │ %ctor / constructor
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IOSDecryptHubLoader.dylib (thin loader)                    │
│  1. Read the bundled enabledBundles.plist config            │
│  2. Check whether the current bundleID is in the enabled    │
│     list                                                    │
│  3. If enabled  → dlopen the main dylib                     │
│  4. If disabled → return immediately (zero overhead)        │
└──────────────────────────┬──────────────────────────────────┘
                           │ dlopen
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  decrypt_helper.dylib (main engine, identical to the        │
│  TrollStore build) — fishhook GOT + ObjC swizzle +          │
│  HTTP/MCP server + floating window                          │
└─────────────────────────────────────────────────────────────┘
```

## Build

```bash
# Build all three debs
make deb

# Build individually
make deb-rootless
make deb-roothide
make deb-rootful

# Or invoke the script directly
./jailbreak/build_deb.sh all
./jailbreak/build_deb.sh rootless
```

Artifacts under `build/deb/`:
- `com.iosdecrypthub.jailbreak_<version>_rootless.deb`
- `com.iosdecrypthub.jailbreak_<version>_roothide.deb`
- `com.iosdecrypthub.jailbreak_<version>_rootful.deb`

## Install Paths

| Root | Loader path | Main dylib path |
|------|-------------|-----------------|
| rootless | `/var/jb/Library/MobileSubstrate/DynamicLibraries/` | `/var/jb/usr/lib/IOSDecryptHub/` |
| roothide | `/var/jb/Library/MobileSubstrate/DynamicLibraries/` | `/var/jb/usr/lib/IOSDecryptHub/` |
| rootful | `/Library/MobileSubstrate/DynamicLibraries/` | `/usr/lib/IOSDecryptHub/` |

## Usage

1. Install the deb for your root via Sileo / Zebra.
2. Open **Settings → IOSDecryptHub**.
3. Tap "Select apps to inject" and turn on the switch for the target app.
4. Restart the target app (or respring) for it to take effect.
5. Open `http://<device IP>:8088` in a browser to view the analysis panel.

**No app is injected by default** — you must enable it manually.

The app selection is stored in `config/enabledBundles.plist` next to the main dylib. On a clean
install, the package creates an empty configuration; during an upgrade it migrates the legacy
`/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist` automatically. The configuration
directory is owned by `mobile`, allowing the Settings pane to update it atomically. The loader
locates it relative to its actual dyld path, avoiding host-app preference container isolation and
rootless `/var/jb` alias differences. The legacy preference domain remains a compatibility fallback.

## Dependencies

- `mobilesubstrate` (>= 0.9.5000) or `ellekit` — dylib loading mechanism
- `preferenceloader` (>= 2.2.6) — loads the IOSDecryptHub pane in Settings
- The settings panel includes its own app selector and does not depend on AppList

## Design Constraints

- ❌ The loader contains no hook logic
- ❌ No inline hooks such as MSHookFunction / %hook
- ❌ No daemon
- ✅ The jailbreak framework is used only as a dylib loader
- ✅ All hooking is done by the main dylib's fishhook + swizzle
