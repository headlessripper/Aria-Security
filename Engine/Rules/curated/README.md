# Curated YARA Rules

Rules in this directory are loaded by Aria Security's YARA scan module
(`RULE_PATH` in `Config/Sys_Config.py` points at `Engine/Rules`, whose
recursive loader picks up this `curated/` subdirectory).

## Sources

### Yara-Rules/rules (community set)

- Repo: https://github.com/Yara-Rules/rules
- Commit: `0f93570194a80d2f2032869055808b0ddcdfb360` (master, dated 2022-04-12)
- License: GNU General Public License v2.0 (see repo's `LICENSE` file)
- Files fetched (verbatim, unmodified) and kept because they compile
  standalone with `yara-python` and require no external modules
  (`pe`, `hash`, `math`, `elf`, etc.) or cross-file `include` statements:

  | File | Original path in Yara-Rules/rules |
  |---|---|
  | `MALW_Eicar.yar` | `malware/MALW_Eicar.yar` |
  | `000_common_rules.yar` | `malware/000_common_rules.yar` |
  | `APT_Blackenergy.yar` | `malware/APT_Blackenergy.yar` |
  | `RAT_Xtreme.yar` | `malware/RAT_Xtreme.yar` |
  | `WShell_ASPXSpy.yar` | `webshells/WShell_ASPXSpy.yar` |
  | `WShell_ChinaChopper.yar` | `webshells/WShell_ChinaChopper.yar` |
  | `Wshell_ChineseSpam.yar` | `webshells/Wshell_ChineseSpam.yar` |

  Several other candidate files from the same repo were tried and
  discarded because they either failed to compile standalone (missing
  `import "pe"` / `import "hash"` dependencies satisfied only when
  compiled as part of the full repo's `index.yar`) or returned 404 at
  the paths probed. Only files that pass `yara.compile()` on their own
  were kept, per the task brief's rule: "if a fetched `.yar` fails to
  compile (imports/deps), remove that file."

### Self-authored

- `aria_test.yar` — written for this project (Aria Security), not
  fetched from any external source. Contains a single rule,
  `Aria_EICAR_Test_File`, matching the standard EICAR antivirus test
  string. This guarantees the curated ruleset is always compilable and
  matchable in CI/tests without needing real malware samples.

## Attribution / license notes

The Yara-Rules/rules project aggregates rules from many contributors;
per-rule `author` metadata (where present) is preserved verbatim in
each file's `meta:` block. The project as a whole is distributed under
GPL-2.0; these files are redistributed here unmodified under the same
license, alongside this project's own `aria_test.yar` (no license
restriction, project-authored).

## Maintenance

If you add more `.yar` files here, verify each one compiles standalone
before committing:

```bash
.venv/Scripts/python.exe -c "import yara; yara.compile(filepath='Engine/Rules/curated/<file>.yar')"
```

Files that require YARA modules (`pe`, `hash`, `math`, `elf`, `cuckoo`,
`magic`) or `include` other files from outside this directory should
not be added unless those dependencies are also vendored and wired
into the scanner's compile step.
