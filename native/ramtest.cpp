// Find the Laptop - RAM test (C++). Several classic memory-test algorithms on a big block. Prints key=value lines.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <new>
#include <vector>
using Clock = std::chrono::steady_clock;
static inline uint64_t xs(uint64_t &s) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
int main() {
    size_t mb = 256; std::vector<uint64_t> *mem = nullptr;
    for (; mb >= 32; mb /= 2) { try { mem = new std::vector<uint64_t>(mb * 1024 * 1024 / 8); break; } catch (const std::bad_alloc &) { mem = nullptr; } }
    if (!mem) { printf("ram_alloc_failed=1\n"); return 0; }
    std::vector<uint64_t> &m = *mem; size_t n = m.size(); uint64_t errors = 0; auto t0 = Clock::now();
    const uint64_t pats[4] = {0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL};
    for (int p = 0; p < 4; p++) { for (size_t i = 0; i < n; i++) m[i] = pats[p]; for (size_t i = 0; i < n; i++) if (m[i] != pats[p]) errors++; }   // solid patterns
    for (int bit = 0; bit < 64; bit++) { uint64_t w = 1ULL << bit; for (size_t i = 0; i < n; i += 4096) m[i] = w; for (size_t i = 0; i < n; i += 4096) if (m[i] != w) errors++; }  // walking ones
    for (size_t i = 0; i < n; i++) m[i] = (uint64_t)i * 0x9E3779B97F4A7C15ULL; for (size_t i = 0; i < n; i++) if (m[i] != (uint64_t)i * 0x9E3779B97F4A7C15ULL) errors++;       // address-in-address
    uint64_t s = 88172645463325252ULL; for (size_t i = 0; i < n; i++) m[i] = xs(s); s = 88172645463325252ULL; for (size_t i = 0; i < n; i++) if (m[i] != xs(s)) errors++; // pseudo-random
    double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    printf("ram_test_mb=%zu\nram_errors=%llu\nram_secs=%.1f\n", mb, (unsigned long long)errors, secs);
    delete mem; return 0;
}
