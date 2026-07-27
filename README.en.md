# IOSDecryptHub

<div align="right">
  <a href="./README.md">中文</a> | <b>English</b>
</div>

IOSDecryptHub is a runtime-analysis dylib injected into iOS app processes. It captures cryptography, file, network, Keychain and dynamic-loading behavior, and ships a web panel, decryption (dumping) and MCP analysis capabilities.

For the full feature set and a live demo, visit: [ios.decrypthub.com](https://ios.decrypthub.com/)

> For your own apps or authorized security testing and research only.

## Getting the dylib

Download `decrypt_helper.dylib` from [GitHub Releases](https://github.com/taisuii/ios-decrypt-helper/releases), or build it yourself:

```bash
make
```

The build artifact is placed at the project root: `decrypt_helper.dylib`.

## Usage

### Option 1: TrollStore Injector (Recommended)

For devices that already have a TrollStore-based injector installed:

1. Select the target app in the injector.
2. Add `decrypt_helper.dylib` and run the injection.
3. Launch the target app.
4. Open `http://<device IP>:8088` in a browser on the same LAN.

Injector UIs vary slightly, but the core operation is always: inject the dylib into the target app, then relaunch the app.

### Option 2: IPA Repackaging

On macOS, first install `insert_dylib`:

```bash
brew install insert_dylib
```

Run the script bundled with the repo:

```bash
./scripts/inject.sh <input.ipa> decrypt_helper.dylib
```

The script produces `hooked_<input>.ipa`. Install / re-sign it with TrollStore, Sideloadly or AltStore, launch the app, then visit:

```text
http://<device IP>:8088
```

### Option 3: TrollStore Manager App

Build and install the dedicated manager IPA:

```bash
make ipa
```

The artifact is placed under `build/trollstore/`. Once installed via TrollStore, you can select the target app and inject directly from within the app.

### PC Auto-Discovery & MCP Gateway

The plugin publishes its actual HTTP port as a `_idh-mcp._tcp.` Bonjour service. After installing `idh`, you no longer need to copy the ever-changing device IP:

```bash
pip install ios-decrypt-hub
idh --devices
idh mcp
```

`idh mcp` converts the device's HTTP MCP into a local stdio MCP, usable as a fixed MCP configuration for clients such as Codex and Claude. The repo's `inject.sh` automatically merges `NSLocalNetworkUsageDescription` and `NSBonjourServices`; when using a third-party injector, the host app or injector must supply these two `Info.plist` declarations.

## Build Variants

| Variant | Command | Purpose |
|---------|---------|---------|
| dev (default) | `make` | Manual injection / local debugging for developers |
| trollstore | `make VARIANT=trollstore` | TrollStore injector / manager IPA |
| jailbreak | `make VARIANT=jailbreak` | Jailbreak deb packages |

### Jailbreak deb Packages (Three Roots)

```bash
make deb              # Build all three: rootless + roothide + rootful
make deb-rootless     # rootless only (Dopamine, etc.)
make deb-roothide     # roothide only
make deb-rootful      # rootful only (classic jailbreaks)
```

Artifacts land in `build/deb/`. Install them via Sileo / Zebra, then choose the apps to inject under Settings → IOSDecryptHub.

## Notes

- The web and MCP services listen on `0.0.0.0:8088` by default with no authentication — use them on trusted networks only.
- Injection, re-signing and decryption capabilities depend on the device environment and the target app's protections.
- Do not post captured keys, passwords, plaintext or other sensitive data to public issues.

Report problems via [GitHub Issues](https://github.com/taisuii/ios-decrypt-helper/issues/new/choose).
