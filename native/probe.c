/* Find the Laptop - C probe. Read-only: asks Windows for hardware facts. Prints key=value lines. */
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
int main(void) {
    SYSTEM_INFO si; MEMORYSTATUSEX ms; SYSTEM_POWER_STATUS sp;
    GetNativeSystemInfo(&si);
    ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    GetSystemPowerStatus(&sp);
    printf("logical_cpus=%lu\n", (unsigned long)si.dwNumberOfProcessors);
    printf("ram_total_mb=%llu\n", (unsigned long long)(ms.ullTotalPhys / 1048576ULL));
    printf("ram_free_mb=%llu\n", (unsigned long long)(ms.ullAvailPhys / 1048576ULL));
    printf("uptime_hours=%.2f\n", (double)GetTickCount64() / 3600000.0);
    printf("ac_line=%d\n", (int)sp.ACLineStatus);
    printf("battery_pct=%d\n", (int)sp.BatteryLifePercent);
    printf("monitors=%d\n", GetSystemMetrics(80));
    printf("screen=%dx%d\n", GetSystemMetrics(0), GetSystemMetrics(1));
    printf("mouse_present=%d\n", GetSystemMetrics(19));
    printf("mouse_buttons=%d\n", GetSystemMetrics(43));
    printf("wheel_present=%d\n", GetSystemMetrics(75));
    printf("touch_digitizer=%d\n", GetSystemMetrics(94));
    printf("kbd_type=%d\n", GetKeyboardType(0));
    printf("kbd_function_keys=%d\n", GetKeyboardType(2));
    return 0;
}
#else
#include <unistd.h>
int main(void) {   /* non-Windows stub, only so the file can be compile-tested */
    printf("logical_cpus=%ld\n", sysconf(_SC_NPROCESSORS_ONLN));
    printf("ram_total_mb=%ld\n", (sysconf(_SC_PHYS_PAGES) / 1024) * (sysconf(_SC_PAGE_SIZE) / 1024));
    return 0;
}
#endif
