// Find the Laptop - C++ probe. Quick CPU + memory benchmark. Prints key=value lines.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
using Clock = std::chrono::steady_clock;
static double ms_since(Clock::time_point t) { return std::chrono::duration<double, std::milli>(Clock::now() - t).count(); }

static uint64_t sieve(uint32_t n) {            // integer work
    std::vector<char> c(n + 1, 1); uint64_t cnt = 0;
    for (uint64_t i = 2; i <= n; i++) {
        if (!c[i]) continue;
        cnt++;
        for (uint64_t j = i * i; j <= n; j += i) c[j] = 0;
    }
    return cnt;
}
static double flops(int iters) {               // floating-point work
    double x = 1.0;
    for (int i = 1; i <= iters; i++) x = x * 1.0000001 + 1.0 / i;
    return x;
}

int main() {
    unsigned threads = std::thread::hardware_concurrency(); if (!threads) threads = 1;
    printf("threads=%u\n", threads);

    // single-thread integer: 3 runs so we can see throttling (slower last run)
    double run[3];
    volatile uint64_t sink = 0;
    for (int r = 0; r < 3; r++) { auto t = Clock::now(); sink += sieve(8000000); run[r] = ms_since(t); }
    printf("int_ms_run1=%.0f\nint_ms_run2=%.0f\nint_ms_run3=%.0f\n", run[0], run[1], run[2]);

    // single vs all-thread float
    auto t1 = Clock::now(); volatile double s1 = flops(60000000); double single = ms_since(t1);
    auto t2 = Clock::now();
    std::vector<std::thread> pool; std::vector<double> res(threads);
    for (unsigned i = 0; i < threads; i++) pool.emplace_back([&res, i] { res[i] = flops(60000000); });
    for (auto &th : pool) th.join();
    double multi = ms_since(t2);
    printf("float_single_ms=%.0f\nfloat_multi_ms=%.0f\n", single, multi);
    printf("multi_core_scaling=%.2f\n", single * threads / (multi > 0 ? multi : 1));

    // memory bandwidth
    const size_t N = 128u * 1024u * 1024u;
    std::vector<char> a(N, 1), b(N, 0);
    double best = 1e18;
    for (int r = 0; r < 3; r++) { auto t = Clock::now(); std::memcpy(b.data(), a.data(), N); double m = ms_since(t); if (m < best) best = m; }
    printf("mem_copy_mb_s=%.0f\n", (N / 1048576.0) / (best / 1000.0));
    printf("check=%d\n", (int)(b[N / 2] + (sink & 1) + (s1 > 0)));
    return 0;
}
