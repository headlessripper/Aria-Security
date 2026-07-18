# Curated YARA Rules

Rules in this directory are intended to be loaded by Aria Security's YARA
scan module (`RULE_PATH` in `Config/Sys_Config.py` points at
`Engine/Rules`, whose recursive loader picks up this `curated/`
subdirectory) — the scanner wiring itself lands in Task 9.

## Sources

### reversinglabs/reversinglabs-yara-rules (permissive set)

- Repo: https://github.com/reversinglabs/reversinglabs-yara-rules
- Commit: `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` (`develop`, dated
  2025-11-03)
- **License: MIT** (see `LICENSE-reversinglabs.txt` in this directory for
  the full notice, copied verbatim from the repo's `LICENSE` file)
- Files fetched verbatim (only the `.yara` -> `.yar` extension was
  changed to match this project's naming and the test harness's glob)
  and kept because they compile standalone with `yara-python`, using
  only the built-in `pe` module (or no module at all) and no cross-file
  `include` statements:

  | File | Original path in reversinglabs-yara-rules | Uses `pe` module |
  |---|---|---|
  | `Win32.Trojan.TrickBot.yar` | `yara/trojan/Win32.Trojan.TrickBot.yara` | no |
  | `Win32.Ransomware.Petya.yar` | `yara/ransomware/Win32.Ransomware.Petya.yara` | yes |
  | `Win32.Trojan.HermeticWiper.yar` | `yara/trojan/Win32.Trojan.HermeticWiper.yara` | no |
  | `Win32.Infostealer.StealC.yar` | `yara/infostealer/Win32.Infostealer.StealC.yara` | no |
  | `Win32.Ransomware.Gpcode.yar` | `yara/ransomware/Win32.Ransomware.Gpcode.yara` | no |

  Several other candidate files from the same repo were tried and
  discarded: `Linux.Virus.Vit.yara` compiles standalone but imports the
  `elf` module, which is outside this project's allowed module set
  (`pe`/`math`/`hash` only); `certificate/blocklist.yara` was skipped for
  size (~600 KB, a certificate-thumbprint blocklist, not a malware
  detection rule); a few more `Win32.Virus.*` / `Win32.Downloader.*`
  files were fetched, compiled cleanly, but left out to keep the curated
  set small and high-signal (quality over quantity per the task brief).
  Only files that pass `yara.compile()` on their own were kept.

### Self-authored

- `aria_test.yar` — written for this project (Aria Security), not
  fetched from any external source. Contains a single rule,
  `Aria_EICAR_Test_File`, matching the standard EICAR antivirus test
  string. This guarantees the curated ruleset is always compilable and
  matchable in CI/tests without needing real malware samples.

## Attribution / license notes

The `Win32.*.yar` files above carry `author = "ReversingLabs"` and
`source = "ReversingLabs"` in their own `meta:` blocks (preserved
verbatim), and the containing repository is distributed under the MIT
License. The MIT copyright notice and permission text are reproduced in
`LICENSE-reversinglabs.txt` alongside this README, as required by the
license. `aria_test.yar` is this project's own work (Aria Security), not
subject to that license.

**The curated ruleset as a whole is now permissively licensed (MIT +
self-authored), replacing the previous GPL-2.0-sourced set.**

## Maintenance

If you add more `.yar` files here, verify each one compiles standalone
before committing:

```bash
.venv/Scripts/python.exe -c "import yara; yara.compile(filepath='Engine/Rules/curated/<file>.yar')"
```

Files that require YARA modules outside `pe`/`math`/`hash` (`elf`,
`cuckoo`, `magic`, etc.) or `include` other files from outside this
directory should not be added unless those dependencies are also
vendored and wired into the scanner's compile step. Prefer sources with
a permissive license (MIT/BSD/Apache-2.0) to keep the whole curated set
license-compatible.
