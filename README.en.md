# IOSDecryptHub

<div align="right">
  <a href="./README.md">中文</a> | <b>English</b>
</div>

IOSDecryptHub is a runtime-analysis dylib injected into iOS app processes. It captures cryptography, file, network, Keychain and dynamic-loading behavior, and ships a web panel, decryption (dumping) and MCP analysis capabilities.

For the full feature set and a live demo, visit: [ios.decrypthub.com](https://ios.decrypthub.com/)

## Editions and Maintenance Branches

The TrollStore and Jailbreak editions are maintained on two long-lived branches:

| Edition | Branch | Focus |
|---------|--------|-------|
| TrollStore | [`main`](https://github.com/taisuii/IOSDecryptHub/tree/main) (default) | Feature scope largely settled; maintain the existing injection and web / MCP architecture, compatibility and stability |
| Jailbreak | [`jailbreak`](https://github.com/taisuii/IOSDecryptHub/tree/jailbreak) | An independently evolving runtime-analysis platform, with Agent / control-plane restructuring, Inline Hook, entry/exit observation and Trace planned |

```bash
git fetch origin
git switch main        # TrollStore development and maintenance
git switch jailbreak   # Jailbreak development; tracks origin/jailbreak on first checkout
```

Build, verify and release the editions independently; an identical core is no longer required. Cherry-pick applicable shared fixes or port them explicitly as the architectures diverge. Do not merge the entire Jailbreak branch back into `main`. Future releases use `trollstore-v<version>` / `jailbreak-v<version>` tags; existing `v*` tags remain unchanged.

### Jailbreak Roadmap

The following features are planned for `jailbreak`; **creating these branches does not mean these enhancements are implemented**:

- **Inline Hook**: cover statically linked functions, direct calls within an image and custom algorithms that fishhook cannot intercept, with argument, return-value and memory-snapshot inspection.
- **Trace**: add function-call tracing and call-chain analysis, and explore instruction-level execution tracing for algorithm and data-flow analysis.
- **Analysis integration**: feed extension events into the existing web / MCP interfaces, with start/stop controls, filtering and export.

Jailbreak v2 follows Android DecryptHub's separation: a lightweight in-process Agent collects and executes, a device Broker routes sessions, and a PC Host owns storage, disassembly, analysis and web / MCP. Inline Hook / Trace live behind Agent backend interfaces and require runtime validation. The current v1 engine remains available during migration.

See the [Jailbreak v2 design](./docs/JAILBREAK_V2_DESIGN.md) for the proposed layout, semantics and staged acceptance criteria. This is a design; v2 is not implemented yet.

## Getting the dylib

Download `decrypt_helper.dylib` from [GitHub Releases](https://github.com/taisuii/IOSDecryptHub/releases), or build it yourself:

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

### PC Connection & MCP Gateway

Install `idh` on your computer and connect to the device manually (the device IP is shown in the app panel or obtained from your LAN):

```bash
pip install ios-decrypt-hub
idh connect <device IP>:8088
idh mcp
```

`idh mcp` converts the device's HTTP MCP into a local stdio MCP, usable as a fixed MCP configuration for clients such as Codex and Claude. `connect` saves the device as a persistent connection; afterwards `devices` / `watch` / `open` / `mcp` use it directly. You can also pass `--endpoint http://<device IP>:8088` for a one-off connection.

## Build Variants

| Variant | Command | Purpose |
|---------|---------|---------|
| dev (default) | `make` | Manual injection / local debugging for developers |
| trollstore | `make VARIANT=trollstore` | TrollStore injector / manager IPA |
| rootless | `make VARIANT=rootless` | Jailbreak deb package |

### Jailbreak deb Package (Rootless / roothide)

Switch to `jailbreak` before packaging. This also requires the sibling repository `../IOSDecryptHubJB/` (or a path set through `DH_JB_DIR`); see [Jailbreak Packaging](./jailbreak/README.md).

```bash
make deb              # Build both standard rootless and roothide packages
make deb-rootless     # Standard rootless (arm64)
make deb-roothide     # roothide (arm64e)
```

Artifacts land in `build/deb/`. Install the package matching the device environment; a standard
rootless package cannot be used on roothide because its arm64 Settings bundle cannot load into an
arm64e process.

## Notes

- The web and MCP services listen on `0.0.0.0:8088` by default with no authentication — use them on trusted networks only.
- Injection, re-signing and decryption capabilities depend on the device environment and the target app's protections.
- Do not post captured keys, passwords, plaintext or other sensitive data to public issues.

Report problems via [GitHub Issues](https://github.com/taisuii/IOSDecryptHub/issues/new/choose).

## License

[MIT](./LICENSE)

Vendored [fishhook](https://github.com/facebook/fishhook) and [Capstone](https://www.capstone-engine.org/) (both BSD-3-Clause); see [NOTICE](./NOTICE).
