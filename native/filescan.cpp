// Find the Laptop - fast file scanner (C++17). Walks folders and prints only "interesting" files as pipe-separated lines:
// F|path|size|mtime|attr|entropy|mz|flags|sha256     flags: dblext, disguised, hidden, hot, packed, script
// Usage: filescan <max_output_lines> <root> [<root> ...]
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif
namespace fs = std::filesystem;

// ---- compact SHA-256
struct Sha256 {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t buf[64]; uint64_t len = 0; size_t n = 0;
    static uint32_t rr(uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }
    void block(const uint8_t *p) {
        static const uint32_t K[64] = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64], a, b, c, d, e, f, g, hh;
        for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
        for (int i = 16; i < 64; i++) { uint32_t s0 = rr(w[i-15],7) ^ rr(w[i-15],18) ^ (w[i-15] >> 3), s1 = rr(w[i-2],17) ^ rr(w[i-2],19) ^ (w[i-2] >> 10); w[i] = w[i-16] + s0 + w[i-7] + s1; }
        a=h[0]; b=h[1]; c=h[2]; d=h[3]; e=h[4]; f=h[5]; g=h[6]; hh=h[7];
        for (int i = 0; i < 64; i++) { uint32_t S1 = rr(e,6)^rr(e,11)^rr(e,25), ch = (e&f)^(~e&g), t1 = hh+S1+ch+K[i]+w[i], S0 = rr(a,2)^rr(a,13)^rr(a,22), mj = (a&b)^(a&c)^(b&c), t2 = S0+mj; hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2; }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void add(const uint8_t *p, size_t l) { len += l; while (l) { size_t t = std::min(l, 64 - n); memcpy(buf + n, p, t); n += t; p += t; l -= t; if (n == 64) { block(buf); n = 0; } } }
    std::string done() {
        uint64_t bits = len * 8; uint8_t pad = 0x80; add(&pad, 1); uint8_t z = 0; while (n != 56) add(&z, 1);
        uint8_t lb[8]; for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i)); add(lb, 8);
        char out[65]; for (int i = 0; i < 8; i++) snprintf(out + 8 * i, 9, "%08x", h[i]); return std::string(out);
    }
};

static std::string lower(std::string s) { for (auto &c : s) c = (char)tolower((unsigned char)c); return s; }
static const std::set<std::string> EXEC = {"exe","dll","scr","com","pif","bat","cmd","vbs","vbe","js","jse","wsf","wsh","hta","ps1","jar","msi"};
static const std::set<std::string> SCRIPT = {"bat","cmd","vbs","vbe","js","jse","wsf","wsh","hta","ps1"};
static const std::set<std::string> DOCS = {"jpg","jpeg","png","gif","bmp","pdf","txt","doc","docx","xls","xlsx","ppt","pptx","mp3","mp4","avi","mkv","rtf","ico","dat","tmp","log","csv"};
static const std::set<std::string> SKIPDIR = {"node_modules",".git","cache","code cache","gpucache","service worker","cachestorage","winsxs","$sysreset","site-packages"};
static const char *HOT[] = {"\\temp\\","/tmp/","\\downloads\\","\\users\\public","$recycle.bin","\\startup\\","\\desktop\\","\\programdata\\","\\appdata\\roaming\\"};

int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: filescan max roots...\n"); return 0; }
    long maxLines = atol(argv[1]), lines = 0; long scanned = 0;
    for (int r = 2; r < argc && lines < maxLines; r++) {
        std::error_code ec; fs::path root = fs::u8path(argv[r]);
        if (!fs::exists(root, ec)) continue;
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end && lines < maxLines; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            const fs::directory_entry &de = *it;
            std::error_code e2;
            if (de.is_directory(e2)) { if (SKIPDIR.count(lower(de.path().filename().string()))) it.disable_recursion_pending(); continue; }
            if (!de.is_regular_file(e2)) continue;
            scanned++;
            std::string name = lower(de.path().filename().string()), ext; size_t dot = name.rfind('.');
            if (dot != std::string::npos) ext = name.substr(dot + 1);
            bool isExec = EXEC.count(ext) > 0, isDoc = DOCS.count(ext) > 0;
            std::string pl = lower(de.path().string()); for (auto &c : pl) if (c == '/') c = '\\';
            bool hot = false; for (auto h : HOT) if (pl.find(h) != std::string::npos) { hot = true; break; }
            uintmax_t size = de.file_size(e2); if (e2) continue;
            std::string flags; bool mz = false; double ent = 0;
            if (isExec && dot != std::string::npos) { std::string stem = name.substr(0, dot); size_t d2 = stem.rfind('.'); if (d2 != std::string::npos && DOCS.count(stem.substr(d2 + 1))) flags += "dblext,"; }
            if (isDoc && size >= 64 && size < 300u * 1024 * 1024) { std::ifstream f(de.path(), std::ios::binary); char b[2] = {0, 0}; f.read(b, 2); if (b[0] == 'M' && b[1] == 'Z') { mz = true; flags += "disguised,"; } }
            int attr = 0;
#ifdef _WIN32
            attr = (int)GetFileAttributesW(de.path().c_str()); if (attr != -1 && (attr & FILE_ATTRIBUTE_HIDDEN) && isExec) flags += "hidden,";
#endif
            if (isExec && SCRIPT.count(ext)) flags += "script,";
            if (isExec && size > 0 && size < 40u * 1024 * 1024) {
                std::ifstream f(de.path(), std::ios::binary); std::vector<unsigned char> b(262144); f.read((char *)b.data(), b.size()); size_t n = (size_t)f.gcount();
                if (n > 1024) { long cnt[256] = {0}; for (size_t i = 0; i < n; i++) cnt[b[i]]++; for (int i = 0; i < 256; i++) if (cnt[i]) { double p = (double)cnt[i] / n; ent -= p * std::log2(p); } if (ent > 7.3 && !SCRIPT.count(ext)) flags += "packed,"; }
            }
            if (hot && isExec) flags += "hot,";
            bool interesting = !flags.empty() && (flags != "script," || hot) && (flags != "hot," || false || ext != "dll");
            if (!interesting) continue;
            if (!flags.empty()) flags.pop_back();
            Sha256 s; { std::ifstream f(de.path(), std::ios::binary); std::vector<uint8_t> b(1 << 16); uintmax_t left = std::min<uintmax_t>(size, 64u * 1024 * 1024); while (f && left) { f.read((char *)b.data(), (std::streamsize)std::min<uintmax_t>(b.size(), left)); std::streamsize g = f.gcount(); if (g <= 0) break; s.add(b.data(), (size_t)g); left -= (uintmax_t)g; } }
            std::string path = de.path().u8string(); std::replace(path.begin(), path.end(), '|', '?');
            auto ft = de.last_write_time(e2); long long mt = 0; if (!e2) mt = (long long)std::chrono::duration_cast<std::chrono::seconds>(ft.time_since_epoch()).count();
            printf("F|%s|%llu|%lld|%d|%.2f|%d|%s|%s\n", path.c_str(), (unsigned long long)size, mt, attr, ent, mz ? 1 : 0, flags.c_str(), s.done().c_str());
            lines++;
        }
    }
    printf("S|scanned=%ld|reported=%ld\n", scanned, lines);
    return 0;
}
