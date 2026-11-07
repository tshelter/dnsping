/*
 * DNS Ping — Linux GUI prototype.
 *
 * Same GUI idea as dnsping (Windows design reference). Native Linux UI, so the exact
 * toolkit is the natural one for this kind of small desktop utility; the important part
 * is that it matches the macOS parity in idea/features, not that it is a portable layer
 * pretending to look the same on every OS.
 *
 * v0.1.0 scope: see PLANS/v0.1.0.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    puts("DNS Ping — Linux GUI prototype");
    puts("Same idea as the Windows dnsping UI; native Linux toolkit to be chosen during implementation.");
    puts("Placeholder for now; real probe core is still the Windows build.");
    return 0;
}
