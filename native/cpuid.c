/* Find the Laptop - CPUID probe (C). Reads the CPU's REAL identity straight from the chip, which software cannot easily fake,
   and measures the true clock speed with the time-stamp counter. Prints key=value lines. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
static double now_s(void) { LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return (double)c.QuadPart / (double)f.QuadPart; }
#else
#include <time.h>
static double now_s(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
#endif
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <x86intrin.h>
int main(void) {
    unsigned a, b, c, d, i; char vendor[13] = {0}, brand[49] = {0}, hv[13] = {0};
    __cpuid(0, a, b, c, d); memcpy(vendor, &b, 4); memcpy(vendor + 4, &d, 4); memcpy(vendor + 8, &c, 4);
    __cpuid(0x80000000u, a, b, c, d);
    if (a >= 0x80000004u) for (i = 0; i < 3; i++) { unsigned r[4]; __cpuid(0x80000002u + i, r[0], r[1], r[2], r[3]); memcpy(brand + 16 * i, r, 16); }
    __cpuid(1, a, b, c, d);
    int hypervisor = (c >> 31) & 1;
    if (hypervisor) { unsigned r[4]; __cpuid(0x40000000u, r[0], r[1], r[2], r[3]); memcpy(hv, &r[1], 4); memcpy(hv + 4, &r[2], 4); memcpy(hv + 8, &r[3], 4); }
    double t0 = now_s(); unsigned long long r0 = __rdtsc(); double t1;
    do { t1 = now_s(); } while (t1 - t0 < 0.25);
    unsigned long long r1 = __rdtsc();
    printf("cpu_vendor=%s\n", vendor);
    printf("cpu_brand=%s\n", brand);
    printf("hypervisor_bit=%d\n", hypervisor);
    printf("hypervisor_vendor=%s\n", hv);
    printf("tsc_ghz=%.3f\n", (double)(r1 - r0) / (t1 - t0) / 1e9);
    return 0;
}
#else
int main(void) { printf("cpu_vendor=non-x86\n"); return 0; }
#endif
