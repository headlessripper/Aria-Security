# Aria Security Minifilter (`Plugins/Filter/`)

A Windows kernel-mode filesystem **minifilter** that scans files on open and
blocks malware before it can be read/executed. Modeled on the WDK `scanner`
sample. This is the final planned component of the Aria Security rebuild.

> ⚠️ **Kernel driver — real risk.** Loading a driver requires admin, test-signing,
> and a reboot, and a buggy driver can **bug-check (BSOD)** the machine. **Test in
> a disposable VM.** The build produces the driver; loading it is your decision.

## How it works

```
 file open ─▶ AriaFilter.sys (kernel)
                │ post-IRP_MJ_CREATE: normalized path
                │ FltSendMessage ─▶ \AriaFilterPort ─▶ aria_filter_bridge.py
                │                                          │ VirusScanner.scan_file(path)
                │ ◀─ reply {SafeToOpen} ◀──────────────────┘
                ▼
     unsafe ▶ fail the open (STATUS_VIRUS_INFECTED)
     clean / timeout / no bridge ▶ allow  (fail-open)
```

- **`AriaFilter/`** — the kernel driver (C). Hooks `IRP_MJ_CREATE` (post-op),
  asks user-mode for a verdict, denies the open on a positive detection.
- **`AriaFilterBridge/aria_filter_bridge.py`** — user-mode service (`ctypes` →
  `fltlib`) that runs the real `VirusScanner` and replies.
- **Safety posture:** the kernel **fails-open** (allows) on timeout / error / no
  connected bridge; the bridge **fails-safe** (allows) on any scanner error or
  missing engine. A file is blocked **only** on an explicit MALWARE/SUSPICIOUS
  verdict.

## Protocol

`AriaFilter/AriaFilter.h` is the single source of truth. `ARIA_SCAN_REQUEST` is
1028 bytes (`ULONG PathLength` + `WCHAR Path[512]`); the Python bridge mirrors it
with `ctypes` and a unit test asserts the size matches
(`tests/filter/test_bridge.py`).

## Build

**Tested path on this repo's box** (WDK headers/libs present, but the WDK's
Visual-Studio MSBuild integration is *not* installed):

```bat
cd Plugins\Filter\AriaFilter
build.bat
```

`build.bat` bootstraps the VS2022 x64 toolchain, auto-detects the newest
`Windows Kits\10` version, and compiles + links `AriaFilter.sys` with `cl`/`link`
against the WDK. Output: `AriaFilter.sys` (unsigned; the `C4324` struct-padding
warnings come from the WDK's own `fltKernel.h` and are harmless).

**On a machine with the WDK Visual-Studio integration**, open/build
`AriaFilter/AriaFilter.vcxproj` (Release|x64) instead.

## Test-sign & install (admin, ideally in a VM)

1. **Enable test-signing** and reboot:
   ```
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
2. **Create + trust a self-signed test certificate** (PowerShell, admin):
   ```powershell
   $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=AriaTest" `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature -KeyExportPolicy Exportable
   $pwd = ConvertTo-SecureString -String "aria" -Force -AsPlainText
   Export-PfxCertificate -Cert $c -FilePath aria.pfx -Password $pwd
   Import-PfxCertificate -FilePath aria.pfx -CertStoreLocation Cert:\LocalMachine\Root -Password $pwd
   Import-PfxCertificate -FilePath aria.pfx -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -Password $pwd
   ```
3. **Sign the driver** (Developer Command Prompt):
   ```
   signtool sign /fd SHA256 /a /n AriaTest /t http://timestamp.digicert.com AriaFilter.sys
   ```
4. **Install & load the minifilter** (admin cmd, from `AriaFilter\`):
   ```
   copy AriaFilter.sys %windir%\System32\drivers\
   rundll32 setupapi,InstallHinfSection DefaultInstall 132 .\AriaFilter.inf
   fltmc load AriaFilter
   fltmc filters              :: confirm "AriaFilter" at altitude 320000
   ```
5. **Start the bridge** (so opens don't just fail-open):
   ```
   python Plugins\Filter\AriaFilterBridge\aria_filter_bridge.py
   ```

## Uninstall

```
fltmc unload AriaFilter
sc delete AriaFilter
del %windir%\System32\drivers\AriaFilter.sys
bcdedit /set testsigning off   :: then reboot
```

## Limitations / future

- **Test-signed only.** Production needs an EV cert + Microsoft attestation and an
  altitude allocated by Microsoft (this uses dev altitude `320000`).
- Single client connection; path-only protocol (the bridge re-reads + scans the
  file). No content streaming, no write/cleanup interception yet.
- **Port synchronization is a known simplification:** `gClientPort` is used in
  `AriaPostCreate` and closed in `AriaPortDisconnect` without a rundown lock, so a
  bridge disconnect during an in-flight scan has a narrow use-after-free window. A
  production hardening pass should guard the port with rundown protection /
  reference counting before real-world use.
- Not auto-launched by the Aria app and not wired into the reachability graph —
  it's a standalone plugin. Wiring kernel detections into `SentinelBrain` events
  and auto-starting the bridge are future work.
