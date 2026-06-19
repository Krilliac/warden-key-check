// wardencheck.cpp
// -----------------------------------------------------------------------------
// WoW Warden client integrity checker  (vanilla 1.12.1  ->  WotLK 3.3.5a)
//
// WHAT THIS DETECTS
//   Warden modules are native x86 code the server sends and the client *executes*
//   after verifying an RSA-2048 signature against a public modulus embedded in
//   WoW.exe (.rdata). If a custom/private-server client ships a *replaced* modulus
//   (attacker-controlled key), that server can sign and run ARBITRARY native code
//   on the player's machine (remote code execution). This tool checks whether the
//   genuine Blizzard Warden key is the one embedded in a given client binary.
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
    uint32_t rva = 0, vsize = 0, fileOff = 0, rawSize = 0;
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
    return 0;
}

static int cmdPin(const std::vector<uint8_t>& b, const std::string& refPath,
                  std::optional<uint64_t> vaOverride, std::optional<int> pick) {
    const PEInfo pe = parsePE(b);
    std::vector<uint8_t> modulus;

    if (vaOverride) {
        const auto off = vaToFileOffset(pe, b, *vaOverride);
        if (!off) {
            std::cerr << "error: VA 0x" << std::hex << *vaOverride
                      << std::dec << " does not map into a section (or <256B remain)\n";
            return 1;
        }
        modulus.assign(b.begin() + *off, b.begin() + *off + MOD_BYTES);
        std::cout << "Pinned modulus from explicit VA, fileOff=0x" << std::hex << *off << std::dec << "\n";
    } else {
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
        std::cout << "Pinned modulus from fileOff=0x" << std::hex << c.offset << std::dec
                  << " (" << c.endian << ", H=" << c.entropy << ")\n";
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

static int cmdScan(const std::vector<uint8_t>& b, const std::string& refPath) {
    const Reference r = loadRef(refPath);
    const std::string fileSha = toHex(sha::sha256(b.data(), b.size()));

    auto banner = [](const char* v, const char* msg){
        std::cout << "\n========================================\n"
                  << "  VERDICT: " << v << "\n"
                  << "  " << msg << "\n"
                  << "========================================\n";
    };

    // 1) Strongest positive signal: exact match against a known-good client.
    if (std::find(r.goodHashes.begin(), r.goodHashes.end(), fileSha) != r.goodHashes.end()) {
        banner("SAFE", "Exact match to a known-good client. Warden key is genuine.");
        std::cout << "full-file sha256: " << fileSha << "\n";
        return 0;
    }

    // Need a pinned reference modulus to judge unknown binaries.
    if (r.modulus.empty()) {
        banner("UNKNOWN", "No reference pinned yet - cannot determine safety.");
        std::cout << "Run:  wardencheck pin <a-client-you-trust>\n"
                     "Verify that trusted client's full-file hash against community consensus first.\n"
                     "One pin covers vanilla through WotLK.\n";
        std::cout << "full-file sha256: " << fileSha << "\n";
        return 3;
    }

    // 2) Content search: is the genuine Blizzard modulus embedded anywhere?
    //    Version-agnostic by design (we match the key, not a fixed offset).
    const auto it = std::search(b.begin(), b.end(), r.modulus.begin(), r.modulus.end());
    if (it != b.end()) {
        const bool pristine = false; // hash already known not in allow-list
        banner("SAFE", "Genuine Blizzard Warden key is embedded in this client.");
        std::cout << "Warden RSA key  : MATCHES trusted reference (server cannot forge modules).\n";
        if (!pristine)
            std::cout << "Note            : full-file hash is not in your known-good list, so the\n"
                         "                  client is modified (e.g. VanillaFixes/SuperWoW-style patch),\n"
                         "                  but the Warden key itself is intact.\n";
        std::cout << "full-file sha256: " << fileSha << "\n";
        return 0;
    }

    // 3) Blizzard key absent. Is a *foreign* RSA-2048 key sitting where the
    //    Warden key belongs? That is the RCE-enabling tamper.
    const PEInfo pe = parsePE(b);
    const auto cands = findModulusCandidates(b, pe.rdataLo, pe.rdataHi);
    if (!cands.empty()) {
        banner("DANGER", "Warden key was REPLACED. Do NOT connect with this client.");
        std::cout << "The genuine Blizzard key is absent and a different RSA-2048 key is embedded.\n"
                     "A server using this client can sign and EXECUTE arbitrary native code on your\n"
                     "machine (remote code execution). Only use the official client for this server.\n";
        std::cout << "foreign key(s)  :\n";
        for (const auto& c : cands)
            std::cout << "    fileOff=0x" << std::hex << c.offset << std::dec
                      << "  sha256=" << toHex(c.sha) << "   (share to blocklist)\n";
        std::cout << "full-file sha256: " << fileSha << "\n";
        return 2;
    }

    // 4) No genuine key, no recognizable foreign key.
    banner("UNKNOWN", "No recognizable Warden key found - treat with caution.");
    std::cout << "Could be a heavily modified, packed, or non-standard client. The Warden key\n"
                 "could not be located to verify it. Prefer an official client from a source you trust.\n";
    std::cout << "full-file sha256: " << fileSha << "\n";
    return 3;
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
    "  wardencheck info    <WoW.exe>           diagnostic dump\n\n"
    "  Options:\n"
    "    --ref <path>       reference store (default: wardencheck.ref)\n"
    "    --offset <hexVA>   pin: read modulus from explicit virtual address\n"
    "    --pick <N>         pin: choose candidate N if several were found\n\n"
    "  Exit codes: 0=SAFE  2=DANGER  3=UNKNOWN  1=usage/error\n\n"
    "  First-time setup: run `pin` once against a client you trust (verify its\n"
    "  full-file hash against community consensus). One pin covers all expansions\n"
    "  because Blizzard reused the same Warden key across 1.12.1 / 2.4.3 / 3.3.5a.\n";
}

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) { usage(); return 1; }

    const std::string cmd = args[0];
    std::string file, refPath = "wardencheck.ref";
    std::optional<uint64_t> vaOverride;
    std::optional<int> pick;

    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "--ref" && i + 1 < args.size())        refPath = args[++i];
        else if (a == "--offset" && i + 1 < args.size()) vaOverride = std::strtoull(args[++i].c_str(), nullptr, 0);
        else if (a == "--pick" && i + 1 < args.size())   pick = std::atoi(args[++i].c_str());
        else if (!a.empty() && a[0] != '-')              file = a;
        else { std::cerr << "error: unknown/!malformed option '" << a << "'\n"; return 1; }
    }

    if (cmd == "help" || cmd == "-h" || cmd == "--help") { usage(); return 0; }

    if (file.empty()) { std::cerr << "error: missing <WoW.exe> path\n"; usage(); return 1; }
    const auto buf = readFile(file);
    if (!buf) { std::cerr << "error: cannot read file: " << file << "\n"; return 1; }

    if (cmd == "scan")    return cmdScan(*buf, refPath);
    if (cmd == "pin")     return cmdPin(*buf, refPath, vaOverride, pick);
    if (cmd == "addgood") return cmdAddGood(*buf, refPath);
    if (cmd == "info")    return cmdInfo(*buf);

    std::cerr << "error: unknown command '" << cmd << "'\n";
    usage();
    return 1;
}
