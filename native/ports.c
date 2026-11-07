/* Find the Laptop - TCP table probe (C). Asks Windows' network driver directly for every TCP connection and its owning process.
   Used to cross-check netstat/psutil: connections that appear here but not elsewhere indicate a hidden connection (rootkit). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
int main(void) {
    DWORD size = 0; PMIB_TCPTABLE_OWNER_PID t; DWORD i;
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    t = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (t && GetExtendedTcpTable(t, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (i = 0; i < t->dwNumEntries; i++) {
            struct in_addr la, ra; char ls[32], rs[32];
            la.s_addr = t->table[i].dwLocalAddr; ra.s_addr = t->table[i].dwRemoteAddr;
            strcpy(ls, inet_ntoa(la)); strcpy(rs, inet_ntoa(ra));
            printf("T|%s|%u|%s|%u|%lu|%lu\n", ls, (unsigned)ntohs((u_short)t->table[i].dwLocalPort), rs, (unsigned)ntohs((u_short)t->table[i].dwRemotePort),
                   (unsigned long)t->table[i].dwState, (unsigned long)t->table[i].dwOwningPid);
        }
    }
    free(t); return 0;
}
#else
int main(void) { printf("T|0.0.0.0|0|0.0.0.0|0|2|0\n"); return 0; }   /* non-Windows stub so the file can be compile-tested */
#endif
