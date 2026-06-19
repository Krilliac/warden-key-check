# wardencheck

A single-file C++17 integrity checker for World of Warcraft client binaries
(vanilla **1.12.1** → WotLK **3.3.5a**). It answers one question:

> Is Blizzard's genuine Warden RSA-2048 public key the one embedded in this
> `WoW.exe`, or has it been swapped for an attacker-controlled key?

## Why this matters

Warden modules are native x86 code the server streams to the client and the
client **executes** — but only after verifying an RSA-2048 signature against a
public modulus baked into `WoW.exe` (`.rdata`). If a private-server client ships
a **replaced** modulus, that server holds the matching private key and can sign
and run **arbitrary native code on the player's machine** (remote code
execution). This tool checks whether the legitimate key is still the one in the
binary.

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
wardencheck info    <WoW.exe>           # diagnostic dump (sections, candidates)
```

Options:

| Option            | Meaning                                                      |
|-------------------|-------------------------------------------------------------|
| `--ref <path>`    | reference store (default: `wardencheck.ref`)                |
| `--offset <hexVA>`| pin: read the modulus from an explicit virtual address      |
| `--pick <N>`      | pin: choose candidate N when several are found              |

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

- It checks whether the genuine key is *present*, not which key the Warden code
  path is actually wired to. A paranoid attacker could embed both keys and route
  to theirs. Catching that needs disassembly of the verify routine (a v2 item).
- The heuristic locator is tuned to **never miss** a key (lenient thresholds);
  false positives are harmless because `pin` lets you confirm with `--pick`.

## Roadmap ideas

- Follow the cross-reference from the Warden signature-verify call site to
  confirm which modulus is actually *live*.
- A bundled known-good hash manifest for common 5875 / 8606 / 12340 locale
  builds so most users never need to pin.
- A small drag-and-drop GUI wrapper for non-technical players.
