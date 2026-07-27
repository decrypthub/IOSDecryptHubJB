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
│  Loads IOSDecryptHubLoader.dylib into all apps (Filter: *)  │
└──────────────────────────┬──────────────────────────────────┘
                           │ %ctor / constructor
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IOSDecryptHubLoader.dylib (thin loader)                    │
│  1. Read plist preferences (com.iosdecrypthub.loader)       │
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

## Dependencies

- `mobilesubstrate` (>= 0.9.5000) or `ellekit` — dylib loading mechanism
- `applist` (>= 1.5) — app-list UI for the settings panel

## Design Constraints

- ❌ The loader contains no hook logic
- ❌ No inline hooks such as MSHookFunction / %hook
- ❌ No daemon
- ✅ The jailbreak framework is used only as a dylib loader
- ✅ All hooking is done by the main dylib's fishhook + swizzle
