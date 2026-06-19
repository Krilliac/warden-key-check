# wardencheck

[![build](https://github.com/Krilliac/warden-key-check/actions/workflows/build.yml/badge.svg)](https://github.com/Krilliac/warden-key-check/actions/workflows/build.yml)

A single-file C++17 integrity checker for World of Warcraft client binaries
(vanilla **1.12.1** → WotLK **3.3.5a**). It answers one question:

> Is Blizzard's genuine Warden RSA-2048 public key the one embedded in this
> `WoW.exe`, or has it been swapped for an attacker-controlled key?

## Why this matters

Warden modules are native x86 code the server streams to the client and the
client **executes** — but only after verifying an RSA-2048 signature against a
public modulus baked into `WoW.exe` (`.rdata`). If a private-server client ships
a **replaced** modulus, that server holds the matching private key and can sign
and load its **own native module**, running **arbitrary native code on the
player's machine** (remote code execution). This tool checks whether the
legitimate key is still the one in the binary.

### What a genuine key does and does not protect against

This is the important nuance (and a correction to an earlier framing of this
project):

- **Genuine key present → no native-code channel.** A server cannot forge a
  custom native module without the matching private key, so it cannot run
  arbitrary native code on you. This is the case wardencheck calls **SAFE**.
- **But a genuine key is not "the server can't touch your client."** Using
  Blizzard's *own* signed module, a server can still issue legitimate Warden
  checks — reading client memory and running **sandboxed Lua** strings. That
  Lua channel is exactly how patch-less custom servers (e.g. **AzerothCore**,
  via its Warden payload manager) add custom UI/content, and it requires **no
  key swap**. It runs in the client's Lua sandbox, not as native code.
- **Replaced key → full native RCE.** Only a swapped modulus lets a server sign
  its *own* native module and execute arbitrary native code — far beyond the
  sandboxed Lua/memory checks the genuine module allows. That is the (relatively
  uncommon) condition wardencheck flags as **DANGER**.

So wardencheck answers one specific question — "can this client's server run
arbitrary *native* code via a replaced Warden key?" — not "can the server
influence my client at all." Sandboxed Lua via the genuine module is expected
and is not flagged.

## Why it is cross-version

Blizzard reused the **same** Warden public key across 1.12.1 / 2.4.3 / 3.3.5a.
Only the byte *offset* of the key in `.rdata` differs per build, so wardencheck
locates the key by **content** (a heuristic search), never by a hardcoded
offset. One trusted reference covers the entire vanilla → WotLK range.

## Honesty model — no fabricated constants

The legitimate modulus is **not** hardcoded. A wrong reference in a security
tool means false "you're safe" verdicts, so instead you establish the reference
once via trust-on-first-use:

1. Pick a client you trust and **verify its full-file SHA-256 against community
   consensus** before pinning.
2. `wardencheck pin <that-client>` extracts the real modulus and stores it.
3. Because the key is shared, that single pin covers every expansion.

## Download

Prebuilt binaries are attached to each [release](https://github.com/Krilliac/warden-key-check/releases/latest)
(built by CI, self-test verified on every platform). Direct links for the latest release:

- Windows x64: `https://github.com/Krilliac/warden-key-check/releases/latest/download/wardencheck-windows-x64.exe`
- Windows x86: `https://github.com/Krilliac/warden-key-check/releases/latest/download/wardencheck-windows-x86.exe`
- Linux x64:   `https://github.com/Krilliac/warden-key-check/releases/latest/download/wardencheck-linux-x64`
- macOS arm64: `https://github.com/Krilliac/warden-key-check/releases/latest/download/wardencheck-macos-arm64`

Windows users can just drag a `WoW.exe` onto the downloaded `.exe`. Or build from source:

## Build

```sh
make                 # or:
g++   -std=c++17 -O2 -Wall -Wextra -o wardencheck wardencheck.cpp
clang++ -std=c++17 -O2 -Wall -Wextra -o wardencheck wardencheck.cpp
cl /std:c++17 /O2 /EHsc /W4 wardencheck.cpp     # MSVC
```

No third-party dependencies — SHA-256 and the PE32 parser are implemented
inline.

## Usage

```sh
wardencheck pin     <trusted-WoW.exe>   # establish reference from a trusted client
wardencheck scan    <WoW.exe>           # verdict: SAFE / DANGER / UNKNOWN
wardencheck addgood <trusted-WoW.exe>   # add a known-good full-file hash
wardencheck info    <WoW.exe>           # diagnostic dump (sections, candidates, xrefs)
wardencheck selftest                    # run built-in self-checks (no file needed)
```

**Drag-and-drop:** drop a `WoW.exe` onto the `wardencheck` executable (or
double-click and pass a path) and it runs `scan` automatically, keeping the
console window open until you press Enter. It stays a terminal tool — no GUI
dependency — but non-technical players never have to touch a command line.

Options:

| Option             | Meaning                                                       |
|--------------------|---------------------------------------------------------------|
| `--ref <path>`     | reference store (default: `wardencheck.ref`)                  |
| `--manifest <path>`| community known-good hash list (default: `wardencheck.manifest`) |
| `--offset <hexVA>` | pin: read the modulus from an explicit virtual address        |
| `--pick <N>`       | pin: choose candidate N when several are found                |
| `--json`           | scan: emit one machine-readable JSON object (for bots/CI)     |

### Machine-readable output (`scan --json`)

For wiring into a Discord bot or CI gate, `scan --json` prints a single JSON
object (and still sets the 0/2/3 exit code):

```json
{"verdict":"DANGER","exit_code":2,"file_sha256":"…","pinned":true,
 "key_present":true,"reversed_match":false,"live_key":"foreign",
 "matched_good_hash":false,"matched_manifest":false,
 "reason":"Genuine key is present but a FOREIGN key is wired in. Do NOT connect.",
 "foreign_keys":[{"sha256":"…","code_referenced":true,"va":4202880,"file_offset":1408}]}
```

### Exact, build-portable pinning

`pin` resolves the **exact** 256-byte key by snapping to the address the verify
code references, rather than a content window that might include adjacent
build-specific bytes. That exactness is what makes a single pin genuinely match
the *same shared key* in every build (1.12.1 → 3.3.5a); a filler-contaminated
pin would fail to match a different legitimate build and raise a false DANGER.
If no code reference is found, it falls back to the content heuristic and warns
that the boundaries are unconfirmed. `scan` also matches the key in either byte
order, so a build that stores it LE-vs-BE is not mistaken for a replacement.

### Known-good manifest

`scan` automatically loads `wardencheck.manifest` (a shippable, community-curated
list of full-file SHA-256s) alongside your local pinned ref, so a recognized
build returns SAFE instantly without pinning. The file ships **empty** — see the
honesty note below — and is populated from community consensus. Point at your own
with `--manifest`.

### Live-key cross-reference (which key is actually wired in?)

Beyond checking that the genuine key is *present*, `scan` follows `imm32`
operands in executable sections to the bytes they point at and classifies them.
This catches the **"embed both keys, route to mine"** evasion: if the genuine
modulus is present but executable code references a *different* modulus and never
the genuine one, the verdict is **DANGER**. This is a lightweight heuristic, not
a full disassembler — it won't see indirect/computed addressing, so the *absence*
of a genuine xref is treated as inconclusive (never as a tamper signal). Only a
*positive* reference to a foreign key escalates the verdict.

## Verdicts and exit codes

| Verdict   | Exit | Meaning                                                                      |
|-----------|------|------------------------------------------------------------------------------|
| `SAFE`    | `0`  | Full-file hash matches a known-good client, **or** the genuine Blizzard key is embedded (notes if the client is otherwise modified, e.g. VanillaFixes/SuperWoW). |
| `DANGER`  | `2`  | Genuine key absent and a *different* RSA-2048 key is present — RCE-capable. Prints the foreign key's SHA-256 for community blocklisting. |
| `UNKNOWN` | `3`  | No reference pinned yet, or no recognizable key found.                       |
| (error)   | `1`  | Usage / I/O error.                                                           |

The 0/2/3 split makes it easy to wire into a Discord bot or CI gate.

## The one thing you must do right

The **pin step is the root of trust**. Verify your reference client's full-file
hash against community consensus *before* pinning — pin a tampered client and
the tool will happily certify that key as "genuine." After a correct pin it is
self-sufficient.

## Honesty caveats

- The live-key cross-reference covers *direct* (`imm32`) key references only.
  Indirect or computed addressing won't be seen, so a missing genuine xref is
  inconclusive — wardencheck escalates to DANGER only on a *positive* reference
  to a foreign key, never on the absence of a genuine one. A full confirmation
  still needs disassembly of the verify routine.
- The heuristic locator is tuned to **never miss** a key (lenient thresholds);
  false positives are harmless because `pin` lets you confirm with `--pick`.
- The manifest ships empty by design (see below) — wardencheck never asserts a
  build is "known-good" on a hash it cannot stand behind.

## Self-test

`wardencheck selftest` runs deterministic checks of the security-critical
primitives (SHA-256 known-answer vectors, the PE32 parser, VA↔file-offset
mapping, the code-xref counter, and the modulus locator) against an in-memory
synthetic PE. Exit code `0` means all checks passed — handy as a CI smoke test.

## Implemented in this version

- **Exact, build-portable pinning** — pins the precise key the verify code
  references, so one pin matches the shared key across every build (and won't
  raise a false DANGER on a different legitimate build).
- **Reversed byte-order match** — a build storing the key LE-vs-BE is not
  mistaken for a replacement.
- **Live-key cross-reference** — follows code pointers to confirm which modulus
  the verify path actually reads (catches the dual-key decoy).
- **Machine-readable `--json`** — single JSON object for Discord-bot/CI wiring.
- **Known-good manifest** — a distributable hash list so most users never pin
  (see `wardencheck.manifest`).
- **Drag-and-drop** — drop a `WoW.exe` onto the executable; stays terminal-based.
- **Built-in `selftest`** — 19 deterministic checks of the security-critical paths.

## Roadmap ideas

- Full disassembly of the signature-verify call site (vs. the current
  direct-reference heuristic) to follow indirect addressing.
- Populating the community manifest for common 5875 / 8606 / 12340 locale builds.
