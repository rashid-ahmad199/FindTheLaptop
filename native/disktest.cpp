// Find the Laptop - disk integrity test (C++). Writes known random data to a temporary file, reads it back and compares.
// Usage: disktest <full path of a temporary file>. The file is deleted afterwards. Prints key=value lines.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <vector>
using Clock = std::chrono::steady_clock;
static inline uint64_t xs(uint64_t &s) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "ftl_disktest.tmp"; const size_t chunk = 1 << 20, chunks = 128;
    std::vector<uint64_t> buf(chunk / 8); FILE *f = fopen(path, "wb");
    if (!f) { printf("disk_error=cannot_create\n"); return 0; }
    uint64_t s = 1234567890123456789ULL; auto t0 = Clock::now(); bool wok = true;
    for (size_t c = 0; c < chunks; c++) { for (auto &x : buf) x = xs(s); if (fwrite(buf.data(), 1, chunk, f) != chunk) { wok = false; break; } }
    fflush(f); fclose(f); double w = std::chrono::duration<double>(Clock::now() - t0).count();
    f = fopen(path, "rb"); if (!f) { printf("disk_error=cannot_reopen\n"); return 0; }
    s = 1234567890123456789ULL; auto t1 = Clock::now(); uint64_t bad = 0, readbytes = 0;
    for (size_t c = 0; c < chunks; c++) { size_t r = fread(buf.data(), 1, chunk, f); readbytes += r; for (size_t i = 0; i < r / 8; i++) if (buf[i] != xs(s)) bad++; if (r != chunk) break; }
    fclose(f); double r = std::chrono::duration<double>(Clock::now() - t1).count(); remove(path);
    printf("disk_write_ok=%d\ndisk_mismatches=%llu\ndisk_write_mb_s=%.0f\ndisk_read_mb_s=%.0f\ndisk_tested_mb=%zu\n", wok ? 1 : 0, (unsigned long long)bad, 128.0 / (w > 0 ? w : 1), 128.0 / (r > 0 ? r : 1), (size_t)(readbytes >> 20));
    return 0;
}
