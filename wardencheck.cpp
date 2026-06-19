// wardencheck.cpp
// -----------------------------------------------------------------------------
// WoW Warden client integrity checker  (vanilla 1.12.1  ->  WotLK 3.3.5a)
//
// WHAT THIS DETECTS
//   Warden modules are native x86 code the server sends and the client *executes*
//   after verifying an RSA-2048 signature against a public modulus embedded in
//   WoW.exe (.rdata). If a custom/private-server client ships a *replaced* modulus
//   (attacker-controlled key), that server can sign and load its OWN native module
//   and run ARBITRARY native code on the player's machine (remote code execution).
//   This tool checks whether the genuine Blizzard Warden key is still embedded.
//
//   SCOPE (important): a genuine key only rules out the *native-code* channel.
//   With Blizzard's own signed module a server can still issue legitimate checks -
//   reading client memory and running SANDBOXED Lua strings. That Lua path is how
//   patch-less custom servers (e.g. AzerothCore's Warden payload manager) add
//   content, and it needs NO key swap. So a replaced key = native RCE (DANGER);
//   a genuine key = no native RCE (SAFE), though sandboxed Lua/memory checks via
//   the legit module are still possible and expected.
//
// WHY IT'S CROSS-VERSION
//   Blizzard reused the SAME Warden public key across 1.12.1 / 2.4.3 / 3.3.5a.
//   Only the byte OFFSET of the key differs per build, so we locate the key by
//   CONTENT (pattern search), never by a hardcoded offset. One trusted reference
//   covers the entire vanilla->WotLK range.
//
// HONESTY MODEL (no fabricated constants)
//   The legitimate modulus is NOT hardcoded. You establish it once via `pin`
//   against a client you trust (verify its full-file hash against community
//   consensus first). The tool extracts the real key and stores it as the
//   reference. Trust-on-first-use; one pin works for all expansions.
//
// BUILD
//   MSVC : cl /std:c++17 /O2 /EHsc /W4 wardencheck.cpp
//   GCC  : g++ -std=c++17 -O2 -Wall -Wextra -o wardencheck wardencheck.cpp
//   Clang: clang++ -std=c++17 -O2 -Wall -Wextra -o wardencheck wardencheck.cpp
//   No third-party dependencies (SHA-256 + PE parsing implemented inline).
//
// USAGE
//   wardencheck pin   <trusted-WoW.exe>      establish reference from a trusted client
//   wardencheck scan  <WoW.exe>              verdict: SAFE / DANGER / UNKNOWN
//   wardencheck addgood <trusted-WoW.exe>    add a known-good full-file hash
//   wardencheck info  <WoW.exe>              diagnostic dump (sections, candidates)
//   Options: --ref <path>  (default: wardencheck.ref)
//            --offset <hex VA>  (pin: read modulus from an explicit virtual address)
//            --pick <N>         (pin: choose candidate N when several are found)
//
// EXIT CODES (for scripting / CI)
//   0 = SAFE      2 = DANGER      3 = UNKNOWN / could not determine      1 = usage/error
// -----------------------------------------------------------------------------

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <optional>
#include <cmath>
#include <cstring>
#include <unordered_set>

// =============================================================================
// SHA-256 (FIPS 180-4). Used for full-file allow-listing and modulus fingerprints.
// Not a hot path (files are ~1.5 MB); clarity over micro-optimization.
// =============================================================================
namespace sha {

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    // Padding: append 0x80, zero-fill to 56 mod 64, then 64-bit big-endian bit length.
    const uint64_t bitlen = static_cast<uint64_t>(len) * 8u;
    std::vector<uint8_t> msg(data, data + len);
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<uint8_t>((bitlen >> (i * 8)) & 0xff));

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(msg[off + i * 4])     << 24) |
                   (uint32_t(msg[off + i * 4 + 1]) << 16) |
                   (uint32_t(msg[off + i * 4 + 2]) <<  8) |
                   (uint32_t(msg[off + i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            const uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1; // intentional uint32 wraparound
        }

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1  = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            const uint32_t ch  = (e & f) ^ (~e & g);
            const uint32_t t1  = hh + S1 + ch + K[i] + w[i];
            const uint32_t S0  = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2  = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    std::array<uint8_t,32> out{};
    for (int i = 0; i < 8; ++i) {
        out[i*4+0] = static_cast<uint8_t>(h[i] >> 24);
        out[i*4+1] = static_cast<uint8_t>(h[i] >> 16);
        out[i*4+2] = static_cast<uint8_t>(h[i] >>  8);
        out[i*4+3] = static_cast<uint8_t>(h[i]);
    }
    return out;
}

} // namespace sha

// =============================================================================
// Small utilities
// =============================================================================
static std::string toHex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 0xf]); }
    return s;
}
static std::string toHex(const std::vector<uint8_t>& v) { return toHex(v.data(), v.size()); }
static std::string toHex(const std::array<uint8_t,32>& a) { return toHex(a.data(), a.size()); }

static std::optional<std::vector<uint8_t>> fromHex(const std::string& s) {
    if (s.size() % 2 != 0) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = nib(s[i]), lo = nib(s[i+1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::optional<std::vector<uint8_t>> readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    f.seekg(0, std::ios::end);
    const std::streamoff sz = f.tellg();
    if (sz < 0) return std::nullopt;
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (sz > 0 && !f.read(reinterpret_cast<char*>(buf.data()), sz)) return std::nullopt;
    return buf;
}

// Little-endian field readers with bounds checking (PE on-disk is LE; this is
// host-endian-independent, no aliasing/alignment UB unlike struct overlays).
static std::optional<uint16_t> rd16(const std::vector<uint8_t>& b, size_t o) {
    if (o + 2 > b.size()) return std::nullopt;
    return static_cast<uint16_t>(b[o] | (uint16_t(b[o+1]) << 8));
}
static std::optional<uint32_t> rd32(const std::vector<uint8_t>& b, size_t o) {
    if (o + 4 > b.size()) return std::nullopt;
    return uint32_t(b[o]) | (uint32_t(b[o+1])<<8) | (uint32_t(b[o+2])<<16) | (uint32_t(b[o+3])<<24);
}

// =============================================================================
// Minimal PE32 parser: locate .rdata bounds and translate VA -> file offset.
// WoW 1.12.1 / 2.4.3 / 3.3.5a clients are all 32-bit (PE32, magic 0x10B).
// =============================================================================
struct Section {
    std::string name;
    uint32_t rva = 0, vsize = 0, fileOff = 0, rawSize = 0, characteristics = 0;
    // IMAGE_SCN_CNT_CODE (0x20) or IMAGE_SCN_MEM_EXECUTE (0x20000000) => holds code.
    bool executable() const { return (characteristics & 0x20000020u) != 0; }
};
struct PEInfo {
    bool ok = false;
    uint32_t imageBase = 0;
    std::vector<Section> sections;
    // .rdata file-offset range (falls back to whole file if .rdata not found)
    size_t rdataLo = 0, rdataHi = 0;
};

static PEInfo parsePE(const std::vector<uint8_t>& b) {
    PEInfo pe;
    // Default scan window = whole file, so any early return below (non-PE,
    // packed, truncated header) still hands callers a usable [lo,hi) range
    // instead of [0,0). The .rdata refinement narrows hi when the section
    // is located. Without this, packed/tampered clients would scan nothing.
    pe.rdataLo = 0;
    pe.rdataHi = b.size();
    auto e_lfanew = rd32(b, 0x3C);
    if (!rd16(b, 0) || *rd16(b, 0) != 0x5A4D /* 'MZ' */ || !e_lfanew) return pe;
    const size_t peoff = *e_lfanew;
    auto sig = rd32(b, peoff);
    if (!sig || *sig != 0x00004550 /* 'PE\0\0' */) return pe;

    auto numSec  = rd16(b, peoff + 6);
    auto optSize = rd16(b, peoff + 20);
    if (!numSec || !optSize) return pe;

    const size_t optOff = peoff + 24;
    auto magic = rd16(b, optOff);
    if (!magic) return pe;
    // PE32 (0x10B): ImageBase is a 4-byte field at optional-header offset +28.
    // PE32+ (0x20B): 8-byte at +24 — not expected for these clients, handled defensively.
    if (*magic == 0x10B) {
        if (auto ib = rd32(b, optOff + 28)) pe.imageBase = *ib;
    } else if (auto ib = rd32(b, optOff + 24)) {
        pe.imageBase = *ib; // low 32 bits suffice for our purposes
    }

    const size_t secStart = optOff + *optSize;
    for (uint16_t i = 0; i < *numSec; ++i) {
        const size_t so = secStart + size_t(i) * 40;
        if (so + 40 > b.size()) break;
        Section s;
        char nm[9] = {0};
        std::memcpy(nm, b.data() + so, 8);
        s.name    = std::string(nm);
        s.vsize   = rd32(b, so + 8).value_or(0);
        s.rva     = rd32(b, so + 12).value_or(0);
        s.rawSize = rd32(b, so + 16).value_or(0);
        s.fileOff = rd32(b, so + 20).value_or(0);
        s.characteristics = rd32(b, so + 36).value_or(0);
        pe.sections.push_back(s);
    }

    // Narrow the heuristic scan window to .rdata when present (the whole-file
    // fallback was already set at function entry).
    for (const auto& s : pe.sections) {
        if (s.name == ".rdata") {
            const size_t lo = s.fileOff;
            size_t hi = size_t(s.fileOff) + s.rawSize;
            if (hi > b.size()) hi = b.size();
            if (lo < hi) { pe.rdataLo = lo; pe.rdataHi = hi; }
            break;
        }
    }
    pe.ok = true;
    return pe;
}

// Translate a virtual address (e.g. 0x005e3a03) to a file offset using sections.
static std::optional<size_t> vaToFileOffset(const PEInfo& pe, const std::vector<uint8_t>& b, uint64_t va) {
    if (!pe.ok || va < pe.imageBase) return std::nullopt;
    const uint64_t rva = va - pe.imageBase;
    for (const auto& s : pe.sections) {
        const uint64_t span = std::max<uint64_t>(s.vsize, s.rawSize);
        if (rva >= s.rva && rva < s.rva + span) {
            const uint64_t off = uint64_t(s.fileOff) + (rva - s.rva);
            if (off + 256 <= b.size()) return static_cast<size_t>(off);
        }
    }
    return std::nullopt;
}

// Inverse mapping: file offset -> virtual address (imageBase + rva).
static std::optional<uint32_t> fileOffsetToVA(const PEInfo& pe, size_t off) {
    if (!pe.ok) return std::nullopt;
    for (const auto& s : pe.sections) {
        if (s.rawSize == 0) continue;
        if (off >= s.fileOff && off < size_t(s.fileOff) + s.rawSize)
            return static_cast<uint32_t>(uint64_t(pe.imageBase) + s.rva + (off - s.fileOff));
    }
    return std::nullopt;
}

// =============================================================================
// Lightweight code cross-reference ("is this key the LIVE one?").
//
// This is NOT a disassembler. WoW's signature-verify path loads the modulus by
// its absolute address, which appears in code as a little-endian imm32 operand
// (e.g. `push offset modulus` / `mov reg, offset modulus`). We count windows in
// executable sections whose 4 bytes equal the key buffer's VA. A nonzero count
// is strong evidence the key at that VA is the one the verify routine reads.
//
// Honest about its limits: indirect/computed addressing won't be caught, so a
// count of 0 is INCONCLUSIVE (not proof the key is dead). A POSITIVE reference
// to a FOREIGN key while the genuine key is unreferenced is the meaningful red
// flag (the "embed both, route to mine" evasion). We only escalate on that
// positive signal, never on an absence.
// =============================================================================
// Count imm32 operands in executable sections whose value lands in [vaLo, vaHi).
static size_t countCodeRefsIntoRange(const std::vector<uint8_t>& b, const PEInfo& pe,
                                     uint32_t vaLo, uint32_t vaHi) {
    size_t count = 0;
    for (const auto& s : pe.sections) {
        if (!s.executable() || s.rawSize == 0) continue;
        const size_t lo = s.fileOff;
        const size_t hi = std::min<size_t>(size_t(s.fileOff) + s.rawSize, b.size());
        if (lo + 4 > hi) continue;
        for (size_t i = lo; i + 4 <= hi; ++i) {
            const uint32_t v = uint32_t(b[i]) | (uint32_t(b[i+1])<<8) |
                               (uint32_t(b[i+2])<<16) | (uint32_t(b[i+3])<<24);
            if (v >= vaLo && v < vaHi) ++count;
        }
    }
    return count;
}
static size_t countCodeRefsToVA(const std::vector<uint8_t>& b, const PEInfo& pe, uint32_t va) {
    return countCodeRefsIntoRange(b, pe, va, va + 1);
}


// =============================================================================
// RSA-2048 modulus heuristic locator.
//
// A 2048-bit RSA modulus n = p*q is: exactly 256 bytes, ODD (product of two odd
// primes), with the top bit set (genuinely 2048-bit), and statistically uniform
// (high distinct-byte count + high entropy). We test both endian storage orders.
// Thresholds are deliberately lenient to avoid MISSING a key (a false negative in
// a security tool is the dangerous direction); occasional false positives are
// harmless because `pin` lets the user confirm/pick.
// =============================================================================
static const size_t MOD_BYTES   = 256;     // 2048 bits
static const int    DISTINCT_MIN = 110;    // random 256B set hits ~162 distinct on avg
static const double ENTROPY_MIN  = 6.0;    // bits/byte; code/ASCII/zero regions fall well below

struct Candidate {
    size_t offset;                         // file offset of the 256-byte window
    std::string endian;                    // "LE" or "BE" interpretation that qualified
    double entropy;
    std::array<uint8_t,32> sha;            // fingerprint of the 256 raw bytes
};

static double windowEntropy(const int counts[256]) {
    double e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        const double p = double(counts[i]) / double(MOD_BYTES);
        e -= p * std::log2(p);
    }
    return e;
}

static std::vector<Candidate> findModulusCandidates(const std::vector<uint8_t>& b,
                                                     size_t lo, size_t hi) {
    std::vector<Candidate> out;
    if (hi > b.size()) hi = b.size();
    if (lo + MOD_BYTES > hi) return out;

    int counts[256] = {0};
    int distinct = 0;
    auto add = [&](uint8_t v){ if (counts[v]++ == 0) ++distinct; };
    auto rem = [&](uint8_t v){ if (--counts[v] == 0) --distinct; };

    for (size_t i = 0; i < MOD_BYTES; ++i) add(b[lo + i]); // prime first window

    long long lastRecorded = -static_cast<long long>(MOD_BYTES); // de-dup overlapping hits
    for (size_t start = lo; start + MOD_BYTES <= hi; ++start) {
        if (start > lo) { rem(b[start - 1]); add(b[start + MOD_BYTES - 1]); }

        // Endianness-aware shape test (cheap, runs every window).
        const uint8_t first = b[start];                 // LE least-significant / BE most-significant
        const uint8_t last  = b[start + MOD_BYTES - 1];  // LE most-significant  / BE least-significant
        const bool le = (first & 1) && (last & 0x80);
        const bool be = (last  & 1) && (first & 0x80);
        if (!le && !be) continue;
        if (distinct < DISTINCT_MIN) continue;

        const double ent = windowEntropy(counts);
        if (ent < ENTROPY_MIN) continue;

        if (static_cast<long long>(start) < lastRecorded + static_cast<long long>(MOD_BYTES)) continue;
        lastRecorded = static_cast<long long>(start);

        Candidate c;
        c.offset  = start;
        c.endian  = le ? "LE" : "BE";
        c.entropy = ent;
        c.sha     = sha::sha256(b.data() + start, MOD_BYTES);
        out.push_back(c);
    }
    return out;
}

// Same shape/entropy test as the locator, but at one FIXED offset (used when we
// follow a code pointer to see whether it lands on a modulus).
static bool isModulusShapedAt(const std::vector<uint8_t>& b, size_t off) {
    if (off + MOD_BYTES > b.size()) return false;
    int counts[256] = {0}; int distinct = 0;
    for (size_t i = 0; i < MOD_BYTES; ++i)
        if (counts[b[off + i]]++ == 0) ++distinct;
    const uint8_t first = b[off], last = b[off + MOD_BYTES - 1];
    const bool le = (first & 1) && (last & 0x80);
    const bool be = (last  & 1) && (first & 0x80);
    if (!le && !be) return false;
    if (distinct < DISTINCT_MIN) return false;
    return windowEntropy(counts) >= ENTROPY_MIN;
}

// =============================================================================
// Live-key resolution: follow every imm32 operand in executable code to the
// bytes it points at, and classify those bytes. This is precise (we test the
// exact pointed-to 256 bytes, no offset guessing) and directly answers "which
// key does the code reference?" - the question the simple content scan cannot.
// =============================================================================
struct CodeKeyRef { uint32_t va; size_t fileOff; std::array<uint8_t,32> sha; };
struct LiveKeyScan {
    bool   genuineReferenced = false;   // code points into the genuine key span
    size_t genuineRefCount   = 0;
    std::vector<CodeKeyRef> foreign;    // distinct shaped keys code points at, elsewhere
};
// genuineLoVA/HiVA: VA span of the genuine modulus as located in THIS binary
// (from a content search). A code pointer landing inside it is the genuine key.
// We classify by span membership, not exact byte equality, because the located
// window can be a few filler bytes off from the true key start - a pointer to
// the real start would otherwise be misread as a foreign key (false DANGER).
// Foreign classification requires the pointed-to bytes to actually be modulus-
// shaped, so coincidental data pointers cannot manufacture a DANGER verdict.
static LiveKeyScan scanCodeReferencedKeys(const std::vector<uint8_t>& b, const PEInfo& pe,
                                          uint32_t genuineLoVA, uint32_t genuineHiVA) {
    LiveKeyScan r;
    if (!pe.ok) return r;
    const bool haveGenuine = genuineHiVA > genuineLoVA;
    std::unordered_set<uint32_t> seen;     // dedupe identical operand values
    for (const auto& s : pe.sections) {
        if (!s.executable() || s.rawSize == 0) continue;
        const size_t lo = s.fileOff;
        const size_t hi = std::min<size_t>(size_t(s.fileOff) + s.rawSize, b.size());
        for (size_t i = lo; i + 4 <= hi; ++i) {
            const uint32_t v = uint32_t(b[i]) | (uint32_t(b[i+1])<<8) |
                               (uint32_t(b[i+2])<<16) | (uint32_t(b[i+3])<<24);
            if (v < pe.imageBase) continue;       // not a plausible VA
            if (!seen.insert(v).second) continue; // already classified this value
            if (haveGenuine && v >= genuineLoVA && v < genuineHiVA) {
                r.genuineReferenced = true; ++r.genuineRefCount; continue;
            }
            const auto off = vaToFileOffset(pe, b, v);
            if (!off || !isModulusShapedAt(b, *off)) continue;
            CodeKeyRef k{v, *off, sha::sha256(b.data() + *off, MOD_BYTES)};
            if (std::none_of(r.foreign.begin(), r.foreign.end(),
                             [&](const CodeKeyRef& e){ return e.sha == k.sha; }))
                r.foreign.push_back(k);
        }
    }
    return r;
}

// =============================================================================
// Reference store (plain text; trivially auditable, no JSON dependency).
//   MODULUS=<512 hex>           the trusted Blizzard Warden modulus (256 bytes)
//   MODULUS_SHA256=<64 hex>     its fingerprint
//   GOODHASH=<64 hex>           full-file SHA-256 of a known-good client (repeatable)
// =============================================================================
struct Reference {
    std::vector<uint8_t> modulus;          // empty if not pinned
    std::string          modulusSha;       // hex
    std::vector<std::string> goodHashes;   // hex full-file SHA-256s
};

static Reference loadRef(const std::string& path) {
    Reference r;
    std::ifstream f(path);
    if (!f) return r;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        const std::string val = line.substr(eq + 1);
        if (key == "MODULUS") {
            if (auto m = fromHex(val)) r.modulus = *m;
        } else if (key == "MODULUS_SHA256") {
            r.modulusSha = val;
        } else if (key == "GOODHASH") {
            if (!val.empty()) r.goodHashes.push_back(val);
        }
    }
    return r;
}

static bool saveRef(const std::string& path, const Reference& r) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    if (!r.modulus.empty()) {
        f << "MODULUS=" << toHex(r.modulus) << "\n";
        f << "MODULUS_SHA256=" << (r.modulusSha.empty()
                                   ? toHex(sha::sha256(r.modulus.data(), r.modulus.size()))
                                   : r.modulusSha) << "\n";
    }
    for (const auto& h : r.goodHashes) f << "GOODHASH=" << h << "\n";
    return static_cast<bool>(f);
}

// =============================================================================
// Distributable known-good manifest (optional, shipped alongside the binary).
//
// Same line format as the reference store but intended to be community-curated
// and version-controlled, so most users get an instant SAFE verdict without
// pinning. Lines starting with '#' are comments; only GOODHASH lines are read
// (a single trusted modulus still belongs in the user's own pinned ref).
//
// HONESTY: this project ships the manifest as a TEMPLATE with documented build
// slots and NO hashes filled in. We do not bake in unverified constants - a
// wrong "known-good" hash is a false "you're safe". Maintainers populate it
// from community consensus; users can point at their own with --manifest.
// =============================================================================
static std::vector<std::string> loadManifestGoodHashes(const std::string& path) {
    std::vector<std::string> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t b0 = line.find_first_not_of(" \t");
        if (b0 == std::string::npos || line[b0] == '#') continue;
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        if (line.substr(0, eq) == "GOODHASH") {
            std::string val = line.substr(eq + 1);
            // tolerate trailing inline comments / whitespace
            size_t sp = val.find_first_of(" \t#");
            if (sp != std::string::npos) val = val.substr(0, sp);
            if (val.size() == 64) out.push_back(val);
        }
    }
    return out;
}

// =============================================================================
// Commands
// =============================================================================
static int cmdInfo(const std::vector<uint8_t>& b) {
    const auto fileSha = sha::sha256(b.data(), b.size());
    std::cout << "File size       : " << b.size() << " bytes\n";
    std::cout << "Full-file SHA256: " << toHex(fileSha) << "\n";

    const PEInfo pe = parsePE(b);
    if (!pe.ok) {
        std::cout << "PE parse        : FAILED (packed/non-PE?) - scanning whole file\n";
    } else {
        std::cout << "PE parse        : ok  imageBase=0x" << std::hex << pe.imageBase << std::dec << "\n";
        std::cout << "Sections        :\n";
        for (const auto& s : pe.sections)
            std::cout << "    " << s.name << "  rva=0x" << std::hex << s.rva
                      << " fileOff=0x" << s.fileOff << " raw=0x" << s.rawSize << std::dec << "\n";
    }

    const auto cands = findModulusCandidates(b, pe.rdataLo, pe.rdataHi);
    std::cout << "RSA-2048 candidates in scan window: " << cands.size() << "\n";
    for (const auto& c : cands)
        std::cout << "    fileOff=0x" << std::hex << c.offset << std::dec
                  << "  " << c.endian << "  H=" << c.entropy
                  << "  sha256=" << toHex(c.sha) << "\n";

    // Code-referenced keys: follow imm32 operands in executable sections to any
    // modulus-shaped bytes they point at (no genuine span here - purely a dump).
    const auto live = scanCodeReferencedKeys(b, pe, 0, 0);
    std::cout << "Code-referenced keys (imm32 -> modulus): " << live.foreign.size() << "\n";
    for (const auto& k : live.foreign)
        std::cout << "    VA=0x" << std::hex << k.va << " fileOff=0x" << k.fileOff << std::dec
                  << "  sha256=" << toHex(k.sha) << "\n";
    return 0;
}

static int cmdPin(const std::vector<uint8_t>& b, const std::string& refPath,
                  std::optional<uint64_t> vaOverride, std::optional<int> pick) {
    const PEInfo pe = parsePE(b);
    std::vector<uint8_t> modulus;
    std::string pinSource;   // human-readable provenance of the pinned bytes

    if (vaOverride) {
        const auto off = vaToFileOffset(pe, b, *vaOverride);
        if (!off) {
            std::cerr << "error: VA 0x" << std::hex << *vaOverride
                      << std::dec << " does not map into a section (or <256B remain)\n";
            return 1;
        }
        modulus.assign(b.begin() + *off, b.begin() + *off + MOD_BYTES);
        pinSource = "explicit VA";
        std::cout << "Pinned modulus from explicit VA, fileOff=0x" << std::hex << *off << std::dec << "\n";
        if (!isModulusShapedAt(b, *off))
            std::cerr << "warning: bytes at this VA are not RSA-2048-modulus-shaped (not 256B with the\n"
                         "         top bit set, odd, and high entropy). Double-check the address - you\n"
                         "         may be pinning the wrong region.\n";
    } else {
        // Prefer the EXACT key the verify code references: a code pointer lands
        // on the true key start, so these bytes are the real 256-byte modulus -
        // identical across builds (the shared key), which is what makes one pin
        // cover every expansion. The content heuristic is a fallback only, since
        // its window can include build-specific filler and would then fail to
        // match a different legitimate build (a false DANGER).
        const auto live = scanCodeReferencedKeys(b, pe, 0, 0);
        if (!live.foreign.empty()) {
            size_t idx = 0;
            if (live.foreign.size() > 1) {
                if (!pick) {
                    std::cerr << "Multiple code-referenced keys found - re-run pin with --pick <N>:\n";
                    for (size_t i = 0; i < live.foreign.size(); ++i)
                        std::cerr << "    [" << i << "] VA=0x" << std::hex << live.foreign[i].va
                                  << " fileOff=0x" << live.foreign[i].fileOff << std::dec
                                  << "  sha256=" << toHex(live.foreign[i].sha) << "\n";
                    return 1;
                }
                if (*pick < 0 || static_cast<size_t>(*pick) >= live.foreign.size()) {
                    std::cerr << "error: --pick out of range (0.." << live.foreign.size()-1 << ")\n";
                    return 1;
                }
                idx = static_cast<size_t>(*pick);
            }
            const auto& k = live.foreign[idx];
            modulus.assign(b.begin() + k.fileOff, b.begin() + k.fileOff + MOD_BYTES);
            pinSource = "code-referenced (exact)";
            std::cout << "Pinned EXACT modulus from code-referenced VA=0x" << std::hex << k.va
                      << " fileOff=0x" << k.fileOff << std::dec << "\n";
        } else {
            // Fallback: content heuristic. Warn that the pin is not code-confirmed.
            const auto cands = findModulusCandidates(b, pe.rdataLo, pe.rdataHi);
            if (cands.empty()) {
                std::cerr << "error: no RSA-2048 modulus candidates found. This may be a packed or\n"
                             "       heavily modified client. Re-run with --offset <hex VA> if you know it.\n";
                return 1;
            }
            size_t idx = 0;
            if (cands.size() > 1) {
                if (!pick) {
                    std::cerr << "Multiple candidates found - re-run pin with --pick <N>:\n";
                    for (size_t i = 0; i < cands.size(); ++i)
                        std::cerr << "    [" << i << "] fileOff=0x" << std::hex << cands[i].offset
                                  << std::dec << "  " << cands[i].endian
                                  << "  H=" << cands[i].entropy
                                  << "  sha256=" << toHex(cands[i].sha) << "\n";
                    return 1;
                }
                if (*pick < 0 || static_cast<size_t>(*pick) >= cands.size()) {
                    std::cerr << "error: --pick out of range (0.." << cands.size()-1 << ")\n";
                    return 1;
                }
                idx = static_cast<size_t>(*pick);
            }
            const auto& c = cands[idx];
            modulus.assign(b.begin() + c.offset, b.begin() + c.offset + MOD_BYTES);
            pinSource = "content heuristic (NOT code-confirmed)";
            std::cout << "Pinned modulus from fileOff=0x" << std::hex << c.offset << std::dec
                      << " (" << c.endian << ", H=" << c.entropy << ")\n";
            std::cerr << "warning: no code reference to this key was found, so the exact byte\n"
                         "         boundaries could not be confirmed. The pin may include adjacent\n"
                         "         bytes and might not match a different build. Prefer pinning a\n"
                         "         client whose verify code references the key, or use --offset.\n";
        }
    }

    Reference r = loadRef(refPath);             // keep any existing good-hash list
    r.modulus    = modulus;
    r.modulusSha = toHex(sha::sha256(modulus.data(), modulus.size()));

    // Also record this trusted client's full-file hash in the allow-list.
    const std::string fileSha = toHex(sha::sha256(b.data(), b.size()));
    if (std::find(r.goodHashes.begin(), r.goodHashes.end(), fileSha) == r.goodHashes.end())
        r.goodHashes.push_back(fileSha);

    if (!saveRef(refPath, r)) { std::cerr << "error: could not write " << refPath << "\n"; return 1; }

    std::cout << "Reference written: " << refPath << "\n";
    std::cout << "  pin source     : " << pinSource << "\n";
    std::cout << "  modulus sha256 : " << r.modulusSha << "\n";
    std::cout << "  added goodhash : " << fileSha << "\n";
    std::cout << "This single reference now covers 1.12.1 / 2.4.3 / 3.3.5a (shared Blizzard key).\n";
    return 0;
}

static int cmdAddGood(const std::vector<uint8_t>& b, const std::string& refPath) {
    Reference r = loadRef(refPath);
    const std::string fileSha = toHex(sha::sha256(b.data(), b.size()));
    if (std::find(r.goodHashes.begin(), r.goodHashes.end(), fileSha) != r.goodHashes.end()) {
        std::cout << "Already present: " << fileSha << "\n";
        return 0;
    }
    r.goodHashes.push_back(fileSha);
    if (!saveRef(refPath, r)) { std::cerr << "error: could not write " << refPath << "\n"; return 1; }
    std::cout << "Added good full-file hash: " << fileSha << "\n";
    return 0;
}

// A foreign key as surfaced in a verdict (code-referenced or content-only).
struct ForeignKey {
    std::string sha;          // hex sha256 of the 256 raw bytes
    uint32_t    va = 0;       // 0 if content-only (no code reference)
    size_t      fileOff = 0;
    bool        codeReferenced = false;
};

struct ScanResult {
    std::string verdict;      // SAFE / DANGER / UNKNOWN
    int         exitCode = 3;
    std::string reason;       // one-line summary
    std::string detail;       // longer human explanation
    std::string fileSha;
    bool        pinned = true;
    bool        keyPresent = false;
    bool        reversedMatch = false;   // genuine key found in opposite byte order
    std::string liveKey = "n/a";         // genuine | foreign | indirect | n/a
    bool        matchedGoodHash = false;
    bool        matchedManifest = false;
    std::vector<ForeignKey> foreignKeys;
};

static ScanResult computeScan(const std::vector<uint8_t>& b, const Reference& r,
                              const std::vector<std::string>& manHashes) {
    ScanResult res;
    res.fileSha = toHex(sha::sha256(b.data(), b.size()));

    // 1) Strongest positive signal: exact match against a known-good client.
    if (std::find(r.goodHashes.begin(), r.goodHashes.end(), res.fileSha) != r.goodHashes.end()) {
        res.verdict = "SAFE"; res.exitCode = 0; res.keyPresent = true; res.liveKey = "genuine";
        res.matchedGoodHash = true;
        res.matchedManifest = std::find(manHashes.begin(), manHashes.end(), res.fileSha) != manHashes.end();
        res.reason = "Exact match to a known-good client. Warden key is genuine.";
        return res;
    }

    // Need a pinned reference modulus to judge unknown binaries.
    if (r.modulus.empty()) {
        res.verdict = "UNKNOWN"; res.exitCode = 3; res.pinned = false;
        res.reason = "No reference pinned yet - cannot determine safety.";
        res.detail = "Run `wardencheck pin <a-client-you-trust>` (verify its hash against community "
                     "consensus first). One pin covers vanilla through WotLK.";
        return res;
    }

    const PEInfo pe = parsePE(b);

    // 2) Content search: is the genuine modulus embedded anywhere? We accept the
    //    stored key in either byte order: builds may store the same key LE or BE,
    //    and matching the reverse avoids a false DANGER on a legitimate variant.
    auto it = std::search(b.begin(), b.end(), r.modulus.begin(), r.modulus.end());
    if (it == b.end()) {
        std::vector<uint8_t> rev(r.modulus.rbegin(), r.modulus.rend());
        it = std::search(b.begin(), b.end(), rev.begin(), rev.end());
        if (it != b.end()) res.reversedMatch = true;
    }
    res.keyPresent = (it != b.end());

    // Precise live-key resolution: follow code pointers to the keys they read.
    uint32_t genuineLoVA = 0, genuineHiVA = 0;
    if (res.keyPresent) {
        const size_t goff = static_cast<size_t>(it - b.begin());
        if (auto va = fileOffsetToVA(pe, goff)) { genuineLoVA = *va; genuineHiVA = *va + MOD_BYTES; }
    }
    const LiveKeyScan live = scanCodeReferencedKeys(b, pe, genuineLoVA, genuineHiVA);

    if (res.keyPresent) {
        // 2a) Decoy / dual-key evasion: genuine key present, but code references a
        //     DIFFERENT modulus and never the genuine one. Escalate only on this
        //     positive foreign reference (absent genuine xref alone is inconclusive).
        if (!live.foreign.empty() && !live.genuineReferenced) {
            res.verdict = "DANGER"; res.exitCode = 2; res.liveKey = "foreign";
            res.reason = "Genuine key is present but a FOREIGN key is wired in. Do NOT connect.";
            res.detail = "The legitimate modulus exists in the file, yet executable code references a "
                         "different RSA-2048 key and never the genuine one (the 'embed both, route to "
                         "mine' pattern). The live verify path uses the attacker's key.";
            for (const auto& k : live.foreign)
                res.foreignKeys.push_back({toHex(k.sha), k.va, k.fileOff, true});
            return res;
        }
        res.verdict = "SAFE"; res.exitCode = 0;
        res.liveKey = live.genuineReferenced ? "genuine" : "indirect";
        res.reason = "Genuine Blizzard Warden key is embedded in this client.";
        res.detail = live.genuineReferenced
            ? "Code references the genuine key directly and no foreign key is referenced."
            : "No direct code xref found (inconclusive - indirect addressing is normal; no foreign "
              "key is referenced either, so no tamper signal). The client is modified (hash not in "
              "the known-good list) but the Warden key itself is intact.";
        res.detail += " Scope: a genuine key means the server cannot forge a custom native Warden "
                      "module, so there is NO arbitrary native-code (RCE) channel. It can still issue "
                      "legitimate checks through Blizzard's signed module - reading client memory and "
                      "running SANDBOXED Lua (standard anti-cheat, and how patch-less custom servers "
                      "like AzerothCore add content). That is expected, not the RCE this tool flags.";
        return res;
    }

    // 3) Genuine key absent. Is a foreign RSA-2048 key present where Warden's belongs?
    const auto cands = findModulusCandidates(b, pe.rdataLo, pe.rdataHi);
    if (!live.foreign.empty() || !cands.empty()) {
        res.verdict = "DANGER"; res.exitCode = 2; res.liveKey = live.foreign.empty() ? "n/a" : "foreign";
        res.reason = "Warden key was REPLACED. Do NOT connect with this client.";
        res.detail = "The genuine Blizzard key is absent and a different RSA-2048 key is embedded. A "
                     "replaced key lets a server sign and load its OWN native Warden module and EXECUTE "
                     "arbitrary native code on your machine (full RCE) - far beyond the sandboxed Lua "
                     "and memory checks the genuine module allows. This is NOT how normal custom "
                     "servers work; they keep the genuine key.";
        if (!live.foreign.empty())
            for (const auto& k : live.foreign)
                res.foreignKeys.push_back({toHex(k.sha), k.va, k.fileOff, true});
        else
            for (const auto& c : cands)
                res.foreignKeys.push_back({toHex(c.sha), 0, c.offset, false});
        return res;
    }

    // 4) No genuine key, no recognizable foreign key.
    res.verdict = "UNKNOWN"; res.exitCode = 3;
    res.reason = "No recognizable Warden key found - treat with caution.";
    res.detail = "Could be a heavily modified, packed, or non-standard client; the Warden key could "
                 "not be located to verify it. Prefer an official client from a source you trust.";
    return res;
}

static void renderHuman(const ScanResult& res) {
    std::cout << "\n========================================\n"
              << "  VERDICT: " << res.verdict << "\n"
              << "  " << res.reason << "\n"
              << "========================================\n";
    if (!res.detail.empty()) std::cout << res.detail << "\n";
    if (res.matchedManifest) std::cout << "matched         : community known-good manifest\n";
    if (res.keyPresent && res.reversedMatch)
        std::cout << "note            : key matched in reversed byte order (LE/BE storage variant).\n";
    if (res.keyPresent && res.verdict == "SAFE")
        std::cout << "live-key xref   : " << res.liveKey << "\n";
    if (!res.foreignKeys.empty()) {
        std::cout << "foreign key(s)  :\n";
        for (const auto& k : res.foreignKeys) {
            std::cout << "    ";
            if (k.codeReferenced) std::cout << "VA=0x" << std::hex << k.va << " ";
            std::cout << "fileOff=0x" << std::hex << k.fileOff << std::dec
                      << (k.codeReferenced ? "  code-referenced" : "")
                      << "  sha256=" << k.sha << "   (share to blocklist)\n";
        }
    }
    std::cout << "full-file sha256: " << res.fileSha << "\n";
}

static void renderJson(const ScanResult& res) {
    auto esc = [](const std::string& s){
        std::string o; o.reserve(s.size()+8);
        for (char c : s) { if (c=='"'||c=='\\') o.push_back('\\'); o.push_back(c); }
        return o;
    };
    std::cout << "{";
    std::cout << "\"verdict\":\"" << res.verdict << "\",";
    std::cout << "\"exit_code\":" << res.exitCode << ",";
    std::cout << "\"file_sha256\":\"" << res.fileSha << "\",";
    std::cout << "\"pinned\":" << (res.pinned ? "true" : "false") << ",";
    std::cout << "\"key_present\":" << (res.keyPresent ? "true" : "false") << ",";
    std::cout << "\"reversed_match\":" << (res.reversedMatch ? "true" : "false") << ",";
    std::cout << "\"live_key\":\"" << res.liveKey << "\",";
    std::cout << "\"matched_good_hash\":" << (res.matchedGoodHash ? "true" : "false") << ",";
    std::cout << "\"matched_manifest\":" << (res.matchedManifest ? "true" : "false") << ",";
    std::cout << "\"reason\":\"" << esc(res.reason) << "\",";
    std::cout << "\"foreign_keys\":[";
    for (size_t i = 0; i < res.foreignKeys.size(); ++i) {
        const auto& k = res.foreignKeys[i];
        std::cout << (i ? "," : "") << "{\"sha256\":\"" << k.sha << "\","
                  << "\"code_referenced\":" << (k.codeReferenced ? "true" : "false") << ","
                  << "\"va\":" << k.va << ",\"file_offset\":" << k.fileOff << "}";
    }
    std::cout << "]}";
    std::cout << "\n";
}

static int cmdScan(const std::vector<uint8_t>& b, const std::string& refPath,
                   const std::string& manifestPath, bool json) {
    Reference r = loadRef(refPath);
    const auto manHashes = loadManifestGoodHashes(manifestPath);
    for (const auto& h : manHashes)
        if (std::find(r.goodHashes.begin(), r.goodHashes.end(), h) == r.goodHashes.end())
            r.goodHashes.push_back(h);

    const ScanResult res = computeScan(b, r, manHashes);
    if (json) renderJson(res); else renderHuman(res);
    return res.exitCode;
}

// =============================================================================
// Self-test: deterministic checks of the security-critical primitives. No I/O,
// no network; safe to run anywhere (CI smoke test). Exit 0 = all passed.
// =============================================================================
static int cmdSelfTest() {
    int failed = 0;
    auto check = [&](bool cond, const char* what){
        std::cout << (cond ? "  ok   " : "  FAIL ") << what << "\n";
        if (!cond) ++failed;
    };

    // 1) SHA-256 known-answer tests (FIPS 180-4).
    {
        const auto e = sha::sha256(reinterpret_cast<const uint8_t*>(""), 0);
        check(toHex(e) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "SHA-256(\"\")");
        const std::string abc = "abc";
        const auto a = sha::sha256(reinterpret_cast<const uint8_t*>(abc.data()), abc.size());
        check(toHex(a) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "SHA-256(\"abc\")");
    }

    // 2) Build a minimal PE32 in memory with a modulus in .rdata and a planted
    //    `push imm32` reference to that modulus's VA in an executable .text.
    auto put16 = [](std::vector<uint8_t>& v, size_t o, uint16_t x){ v[o]=uint8_t(x); v[o+1]=uint8_t(x>>8); };
    auto put32 = [](std::vector<uint8_t>& v, size_t o, uint32_t x){
        v[o]=uint8_t(x); v[o+1]=uint8_t(x>>8); v[o+2]=uint8_t(x>>16); v[o+3]=uint8_t(x>>24); };

    const uint32_t IMAGE_BASE = 0x00400000;
    const size_t peoff = 0x40, optSize = 0xE0, optOff = peoff + 24;
    const size_t secStart = optOff + optSize;

    std::vector<uint8_t> mod(MOD_BYTES);
    for (size_t i = 0; i < MOD_BYTES; ++i) mod[i] = uint8_t((i * 37 + 11) ^ (i >> 1)); // pseudo-random
    mod[0] |= 0x80; mod[MOD_BYTES-1] |= 0x01;                                          // shape: BE top+odd

    // .text raw and .rdata raw placement (512-aligned).
    const size_t textRaw  = ((secStart + 2*40) + 0x1FF) & ~size_t(0x1FF);
    const size_t textSize = 0x40;
    const size_t rdataRaw = textRaw + 0x200;
    const size_t fillerPre = 0x80;
    const size_t modRaw = rdataRaw + fillerPre;
    const size_t rdataSize = fillerPre + MOD_BYTES + 0x80;
    const uint32_t textRVA = 0x1000, rdataRVA = 0x2000;
    const uint32_t modVA = uint32_t(IMAGE_BASE + rdataRVA + fillerPre);

    std::vector<uint8_t> b(rdataRaw + rdataSize, 0x00);
    b[0] = 'M'; b[1] = 'Z';
    put32(b, 0x3C, uint32_t(peoff));
    put32(b, peoff, 0x00004550);
    put16(b, peoff + 6, 2);            // NumberOfSections
    put16(b, peoff + 20, uint16_t(optSize));
    put16(b, optOff, 0x10B);          // PE32
    put32(b, optOff + 28, IMAGE_BASE);
    // .text header
    {
        const char* nm = ".text"; std::memcpy(b.data()+secStart, nm, 5);
        put32(b, secStart + 8, textSize); put32(b, secStart + 12, textRVA);
        put32(b, secStart + 16, uint32_t(textSize)); put32(b, secStart + 20, uint32_t(textRaw));
        put32(b, secStart + 36, 0x60000020); // CNT_CODE|MEM_EXECUTE|MEM_READ
    }
    // .rdata header
    {
        const size_t so = secStart + 40;
        const char* nm = ".rdata"; std::memcpy(b.data()+so, nm, 6);
        put32(b, so + 8, uint32_t(rdataSize)); put32(b, so + 12, rdataRVA);
        put32(b, so + 16, uint32_t(rdataSize)); put32(b, so + 20, uint32_t(rdataRaw));
        put32(b, so + 36, 0x40000040); // CNT_INITIALIZED_DATA|MEM_READ
    }
    // plant code: push imm32 (0x68) <modVA LE>
    b[textRaw] = 0x68; put32(b, textRaw + 1, modVA);
    // copy filler + modulus
    for (size_t i = 0; i < fillerPre; ++i) b[rdataRaw + i] = 0x11;
    std::memcpy(b.data() + modRaw, mod.data(), MOD_BYTES);

    const PEInfo pe = parsePE(b);
    check(pe.ok, "parsePE: valid PE");
    check(pe.imageBase == IMAGE_BASE, "parsePE: imageBase");
    check(pe.sections.size() == 2, "parsePE: section count");
    check(pe.rdataLo == rdataRaw && pe.rdataHi == rdataRaw + rdataSize, "parsePE: .rdata window");

    if (auto va = fileOffsetToVA(pe, modRaw))
        check(*va == modVA, "fileOffsetToVA(modulus) round-trip");
    else check(false, "fileOffsetToVA returned nullopt");

    check(countCodeRefsToVA(b, pe, modVA) == 1, "countCodeRefsToVA: finds planted push imm32");
    check(countCodeRefsToVA(b, pe, modVA + 0x1234) == 0, "countCodeRefsToVA: no false positive");

    const auto cands = findModulusCandidates(b, pe.rdataLo, pe.rdataHi);
    check(!cands.empty(), "findModulusCandidates: locates a key in .rdata");

    const auto found = std::search(b.begin(), b.end(), mod.begin(), mod.end());
    check(found != b.end(), "std::search: genuine modulus is findable by content");

    // 3) Exact-key extraction: the code-referenced key resolves to the TRUE key
    //    start (modRaw), not the heuristic window - this is what makes a pin
    //    byte-exact and therefore portable across builds.
    const auto live = scanCodeReferencedKeys(b, pe, 0, 0);
    check(live.foreign.size() == 1, "scanCodeReferencedKeys: exactly one code-referenced key");
    if (!live.foreign.empty()) {
        check(live.foreign[0].fileOff == modRaw, "code-referenced key offset is the EXACT key start");
        check(std::equal(mod.begin(), mod.end(), b.begin() + live.foreign[0].fileOff),
              "code-referenced bytes equal the planted modulus");
    }

    // 4) Verdict logic via computeScan against an in-memory reference.
    {
        Reference rg; rg.modulus = mod; rg.modulusSha = toHex(sha::sha256(mod.data(), mod.size()));
        const ScanResult sr = computeScan(b, rg, {});
        check(sr.verdict == "SAFE" && sr.exitCode == 0, "computeScan: genuine pinned key -> SAFE");
        check(sr.liveKey == "genuine", "computeScan: live-key resolved to genuine");

        std::vector<uint8_t> other(MOD_BYTES);
        for (size_t i = 0; i < MOD_BYTES; ++i) other[i] = uint8_t((i * 53 + 7) ^ 0xA5);
        other[0] |= 0x80; other[MOD_BYTES-1] |= 0x01;
        Reference rf; rf.modulus = other; rf.modulusSha = toHex(sha::sha256(other.data(), other.size()));
        const ScanResult df = computeScan(b, rf, {});
        check(df.verdict == "DANGER" && df.exitCode == 2, "computeScan: foreign pinned key -> DANGER");

        Reference rh; rh.goodHashes.push_back(toHex(sha::sha256(b.data(), b.size())));
        const ScanResult hs = computeScan(b, rh, rh.goodHashes);
        check(hs.verdict == "SAFE" && hs.matchedManifest, "computeScan: manifest hash match -> SAFE");

        Reference re; // empty (no pin)
        const ScanResult un = computeScan(b, re, {});
        check(un.verdict == "UNKNOWN" && !un.pinned, "computeScan: no pin -> UNKNOWN");
    }

    std::cout << (failed ? "\nSELFTEST: FAILED (" : "\nSELFTEST: PASSED (")
              << failed << " failure" << (failed==1?"":"s") << ")\n";
    return failed ? 1 : 0;
}

// =============================================================================
// CLI
// =============================================================================
static void usage() {
    std::cout <<
    "wardencheck - WoW Warden client integrity checker (1.12.1 -> 3.3.5a)\n\n"
    "  wardencheck pin     <trusted-WoW.exe>   establish reference from a trusted client\n"
    "  wardencheck scan    <WoW.exe>           verdict: SAFE / DANGER / UNKNOWN\n"
    "  wardencheck addgood <trusted-WoW.exe>   add a known-good full-file hash\n"
    "  wardencheck info    <WoW.exe>           diagnostic dump\n"
    "  wardencheck selftest                    run built-in self-checks (no file needed)\n\n"
    "  Drag-and-drop: drop a WoW.exe onto the wardencheck executable to scan it\n"
    "                 (the window stays open until you press Enter).\n\n"
    "  Options:\n"
    "    --ref <path>       reference store (default: wardencheck.ref)\n"
    "    --manifest <path>  community known-good hash list (default: wardencheck.manifest)\n"
    "    --offset <hexVA>   pin: read modulus from explicit virtual address\n"
    "    --pick <N>         pin: choose candidate N if several were found\n"
    "    --json             scan: emit one machine-readable JSON object (for bots/CI)\n\n"
    "  Exit codes: 0=SAFE  2=DANGER  3=UNKNOWN  1=usage/error\n\n"
    "  First-time setup: run `pin` once against a client you trust (verify its\n"
    "  full-file hash against community consensus). One pin covers all expansions\n"
    "  because Blizzard reused the same Warden key across 1.12.1 / 2.4.3 / 3.3.5a.\n";
}

static bool isCommand(const std::string& s) {
    return s == "pin" || s == "scan" || s == "addgood" || s == "info" ||
           s == "selftest" || s == "help" || s == "-h" || s == "--help";
}

// Block until the user presses Enter, so a double-click / drag-and-drop console
// window does not vanish before the verdict can be read.
static void pauseForUser() {
    std::cout << "\nPress Enter to close this window..." << std::flush;
    std::string dummy;
    std::getline(std::cin, dummy);
}

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) { usage(); return 1; }

    // Drag-and-drop / double-click: the first arg is a file path, not a verb.
    // Default to `scan` and keep the console open afterwards.
    bool dragDrop = false;
    std::string cmd = args[0];
    if (!isCommand(cmd) && !cmd.empty() && cmd[0] != '-') {
        std::ifstream probe(cmd, std::ios::binary);
        if (probe.good()) { dragDrop = true; args.insert(args.begin(), "scan"); cmd = "scan"; }
    }

    std::string file;
    std::string refPath = "wardencheck.ref";
    std::string manifestPath = "wardencheck.manifest";
    std::optional<uint64_t> vaOverride;
    std::optional<int> pick;
    bool json = false;

    auto fail = [&](const std::string& msg) -> int {
        std::cerr << msg << "\n";
        if (dragDrop) pauseForUser();
        return 1;
    };

    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "--ref" && i + 1 < args.size())          refPath = args[++i];
        else if (a == "--manifest" && i + 1 < args.size()) manifestPath = args[++i];
        else if (a == "--offset" && i + 1 < args.size())   vaOverride = std::strtoull(args[++i].c_str(), nullptr, 0);
        else if (a == "--pick" && i + 1 < args.size())     pick = std::atoi(args[++i].c_str());
        else if (a == "--json")                            json = true;
        else if (!a.empty() && a[0] != '-')                file = a;
        else return fail("error: unknown/malformed option '" + a + "'");
    }

    if (cmd == "help" || cmd == "-h" || cmd == "--help") { usage(); return 0; }
    if (cmd == "selftest") return cmdSelfTest();

    if (file.empty()) { std::cerr << "error: missing <WoW.exe> path\n"; usage(); return 1; }
    const auto buf = readFile(file);
    if (!buf) return fail("error: cannot read file: " + file);

    int rc;
    if      (cmd == "scan")    rc = cmdScan(*buf, refPath, manifestPath, json);
    else if (cmd == "pin")     rc = cmdPin(*buf, refPath, vaOverride, pick);
    else if (cmd == "addgood") rc = cmdAddGood(*buf, refPath);
    else if (cmd == "info")    rc = cmdInfo(*buf);
    else return fail("error: unknown command '" + cmd + "'");

    if (dragDrop) pauseForUser();
    return rc;
}
