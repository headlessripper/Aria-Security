# Aria Security

An AI-powered antivirus and system-defence platform for Windows.

Aria combines a real machine-learning PE classifier with YARA rules, hash
signatures, certificate reputation and behavioural analysis, and pairs them with
live network, ransomware, exploit and removable-storage protection — all driven
from a single local web UI and an embedded security assistant.

> **Status:** active development. The user-mode product is complete and
> packageable. The kernel minifilter builds but is **not** production-signed, so
> it is dev/test only — see [Kernel driver](#kernel-driver-devtest-only).

---

## Highlights

- **Real ML detection.** A LightGBM model trained on the full EMBER 2018 labelled
  set (300k benign / 300k malicious), exported to ONNX. **Holdout AUC 0.99755.**
- **Four-layer file verdict.** ML score, fuzzy/import hashing, YARA rules and
  Authenticode certificate reputation are fused by an explicit precedence policy
  rather than a single signal.
- **Live protection.** Network reputation/IOC blocking, ransomware canaries and
  entropy analysis, exploit-chain detection, behavioural rules, and a port-scan /
  SYN-flood defence.
- **All your drives.** Real-time monitoring covers the user profile plus every
  attached fixed and removable drive — USB sticks and external HDD/SSDs included —
  and picks up drives plugged in later without a restart.
- **Sentinel Sense.** Tracks what each installer puts on the machine and, after an
  uninstall, shows the leftovers as a data tree and offers to remove them.
- **Argus.** An embedded security assistant that runs *without* a model
  (deterministic command routing over real tools) and gets richer when a local
  GGUF is present. Destructive actions are confirmation-gated.

## Architecture

```
        ┌──────────────────────────────┐
        │  UI: Flutter shell / WebView │   custom frameless window
        └──────────────┬───────────────┘
                       │  HTTP + Socket.IO
        ┌──────────────▼───────────────┐
        │  Flask app (127.0.0.1:8765)  │   85 REST routes, live events
        └──────────────┬───────────────┘
                       │
   ┌───────────────────┼────────────────────┐
   │                   │                    │
┌──▼──────────┐  ┌─────▼────────┐  ┌────────▼────────┐
│ Detection   │  │ Protection   │  │ Support         │
│ engine      │  │ services     │  │ services        │
│ ML · YARA   │  │ network ·    │  │ vault · history │
│ hash · cert │  │ ransom ·     │  │ scheduler ·     │
│ · fusion    │  │ exploit ·    │  │ whitelist ·     │
│             │  │ storage      │  │ sense · Argus   │
└──────┬──────┘  └──────┬───────┘  └────────┬────────┘
       └────────────────┼───────────────────┘
                 ┌──────▼───────┐
                 │ SentinelBrain│  event bus + protection level
                 └──────────────┘
```

The UI is a pure client: it only talks HTTP and Socket.IO, so nothing in the
engine or services knows how it is displayed.

## Requirements

- Windows 10/11 (x64)
- Python 3.11 (to run from source)
- Administrator rights — an AV needs them for firewall rules and quarantine
- Optional: [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
  for the Flutter shell (preinstalled on Windows 11)

## Running from source

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python SentinelUI_Flask.py
```

This starts the backend and opens the desktop window. To run headless and use a
browser instead, pass `--no-elevate` and open <http://127.0.0.1:8765>.

## Building

### Desktop application

```bash
.venv\Scripts\python -m PyInstaller packaging\aria.spec --noconfirm
```
→ `dist\AriaSecurity\AriaSecurity.exe` (self-contained; no Python needed)

### Windows service

```bash
.venv\Scripts\python -m PyInstaller packaging\aria_service.spec --noconfirm
```
→ `dist\AriaService\AriaService.exe`

Run as administrator:

```bash
AriaService.exe install     # register, auto-start
AriaService.exe start
AriaService.exe stop
AriaService.exe remove
AriaService.exe debug       # run in the console
```

As a service Aria runs as **LocalSystem**: protection starts before login,
survives the window being closed, and elevates once at install time instead of
prompting on every launch.

### UI shell (Flutter)

```bash
cd Client
flutter pub get
flutter build windows --release
```
→ `Client\build\windows\x64\runner\Release\aria_shell.exe`

A thin frameless window that displays the UI. It does **not** start the backend.

### Installer

```bash
iscc packaging\Aria.iss
```
→ `dist\installer\AriaSecurity-Setup-<version>.exe`

Installs the service, registers it, and installs the UI shell alongside.

## Where data lives

| Context | Location |
|---|---|
| Desktop run | `%USERPROFILE%\.AriaSecurity` |
| Service (LocalSystem) | `%ProgramData%\AriaSecurity` |
| Override | `ARIA_DATA_DIR` |

Holds the whitelist, quarantine, secure vault, scan history, schedules, the
Sense map and Argus history. Desktop data is migrated into the machine-wide
directory on first service start.

Under `%ProgramData%` the ACL is `SYSTEM`/`Administrators: FullControl`,
`Users: ReadAndExecute` — deliberate, so quarantine and whitelist are
tamper-resistant for non-admin users. All writes go through the service.

**Uninstalling leaves this directory in place** — quarantined files and the vault
are your data, not install artefacts.

## Detection engine

| Layer | What it does |
|---|---|
| **ML** | EMBER 2381-dim features → LightGBM → ONNX. AUC 0.99755 |
| **Hash** | MD5/SHA-256 signature sets |
| **Fuzzy** | Import hashing + TLSH (degrades gracefully if unavailable) |
| **YARA** | Curated rule namespaces, user-extendable from the UI |
| **Certificate** | Authenticode via WinVerifyTrust, embedded **and** catalog signatures |
| **Fusion** | Explicit precedence policy over all of the above |

Retrain against your own dataset:

```bash
python -m Engine.Properties.vectorize_ember --data <ember_dir> --out <out> --split train --labeled-only
python -m Engine.Properties.train --data <out> --format ember --max-rows 200000
```

`--max-rows` caps a class-balanced subsample so training fits in available RAM.

## Kernel driver (dev/test only)

`Plugins/Filter/` contains a filesystem minifilter that scans files on open and
fails infected opens with `STATUS_VIRUS_INFECTED`, consulting the user-mode
engine over an FltMgr port. It **fails open**: if no bridge is connected or the
round-trip times out, access is allowed.

It compiles (`build.bat`, WDK) but is **test-signed on a development altitude**.
Loading it requires test-signing mode and a reboot, and a faulty kernel driver
can bug-check the machine — **use a VM**. Production distribution needs an EV
certificate, Microsoft attestation signing and an allocated altitude; see
`Plugins/Filter/README.md`.

The rest of Aria is user-mode and needs none of this.

## Development

```bash
.venv\Scripts\python -m pytest tests\ -q          # test suite
.venv\Scripts\python scripts\verify_reachability.py   # dead-code gate
```

`verify_reachability.py` walks imports from the entry point and fails if the live
module count drifts, or if anything under a retired `cleanup/` path becomes
reachable again.

Design documents and implementation plans live in `docs/superpowers/`.

## Project layout

```
Engine/         detection engine (compiler, ML, YARA, signatures, model)
Services/       protection + support services, brain, monitors
Argus/          embedded security assistant
Interface/      shared helpers, icons
Actions/        response actions (quarantine, terminate)
Config/         configuration and path resolution
templates/      the single-page UI
Client/         Flutter Windows shell
Plugins/Filter/ kernel minifilter (dev/test)
packaging/      PyInstaller specs + Inno Setup installer
tests/          test suite
docs/           design specs and plans
```

## Security notes

- Aria needs administrator rights; that is inherent to what it does.
- API keys in `Config/Config.json` are stored in plaintext. Treat that file as a
  secret and do not commit real keys.
- Builds are unsigned, so SmartScreen will warn on other machines until they are
  signed with a code-signing certificate.
- **Never commit PE binaries to this repository** — Aria's own scanner quarantines
  PE bytes found inside `.git` pack objects, which will corrupt the repo. Build
  outputs are gitignored for exactly this reason.

## License

Proprietary. The full *Aria Security AI Antivirus License Agreement* is bundled
in `Config/Sys_Config.py` and shown at install time. It grants a non-exclusive,
non-transferable licence for personal or internal business use; redistribution,
sublicensing and reverse engineering are not permitted.

---

*Aria Security — developed by Samuel Ikenna Great.*
