/*
 * Tests for bgp_print.c functions, specifically ipv4_string()
 *
 * This test validates that IPv4 addresses are correctly converted to
 * dotted-quad strings.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "testhelp.h"

/* Forward declaration - we need to link with bgp_print.o */
extern char *ipv4_string(uint32_t ipv4);

/*
 * Test ipv4_string() with host byte order input
 *
 * The ipv4_string() function expects host byte order input, as converted
 * by uchar_be_to_uint32() from network byte order.
 *
 * Example: 172.28.0.2
 * - Network bytes on wire: [0xAC, 0x1C, 0x00, 0x02]
 * - After uchar_be_to_uint32(): 0xAC1C0002 (host order)
 */
void test_ipv4_string_host_order(void) {
    test_section("ipv4_string() with host byte order input");
    char *result;

    /*
     * Test case 1: 172.28.0.2 (the actual failing case from integration tests)
     * Network bytes: [0xAC, 0x1C, 0x00, 0x02]
     * Host order (after uchar_be_to_uint32): 0xAC1C0002
     */
    result = ipv4_string(0xAC1C0002);
    test_cond("172.28.0.2 (host order 0xAC1C0002)",
        result != NULL && strcmp(result, "172.28.0.2") == 0);
    if (result) {
        if (strcmp(result, "172.28.0.2") != 0) {
            printf("   Expected: 172.28.0.2, Got: %s\n", result);
        }
        free(result);
    }

    /*
     * Test case 2: 192.168.1.1
     * Network bytes: [0xC0, 0xA8, 0x01, 0x01]
     * Host order: 0xC0A80101
     */
    result = ipv4_string(0xC0A80101);
    test_cond("192.168.1.1 (host order 0xC0A80101)",
        result != NULL && strcmp(result, "192.168.1.1") == 0);
    if (result) {
        if (strcmp(result, "192.168.1.1") != 0) {
            printf("   Expected: 192.168.1.1, Got: %s\n", result);
        }
        free(result);
    }

    /*
     * Test case 3: 10.0.0.1
     * Network bytes: [0x0A, 0x00, 0x00, 0x01]
     * Host order: 0x0A000001
     */
    result = ipv4_string(0x0A000001);
    test_cond("10.0.0.1 (host order 0x0A000001)",
        result != NULL && strcmp(result, "10.0.0.1") == 0);
    if (result) {
        if (strcmp(result, "10.0.0.1") != 0) {
            printf("   Expected: 10.0.0.1, Got: %s\n", result);
        }
        free(result);
    }

    /*
     * Test case 4: 255.255.255.255 (broadcast)
     */
    result = ipv4_string(0xFFFFFFFF);
    test_cond("255.255.255.255 (all ones)",
        result != NULL && strcmp(result, "255.255.255.255") == 0);
    if (result) {
        if (strcmp(result, "255.255.255.255") != 0) {
            printf("   Expected: 255.255.255.255, Got: %s\n", result);
        }
        free(result);
    }

    /*
     * Test case 5: 0.0.0.0 (any/unspecified)
     */
    result = ipv4_string(0x00000000);
    test_cond("0.0.0.0 (all zeros)",
        result != NULL && strcmp(result, "0.0.0.0") == 0);
    if (result) {
        if (strcmp(result, "0.0.0.0") != 0) {
            printf("   Expected: 0.0.0.0, Got: %s\n", result);
        }
        free(result);
    }

    /*
     * Test case 6: 1.2.3.4 (ascending octets)
     * Host order: 0x01020304
     */
    result = ipv4_string(0x01020304);
    test_cond("1.2.3.4 (host order 0x01020304)",
        result != NULL && strcmp(result, "1.2.3.4") == 0);
    if (result) {
        if (strcmp(result, "1.2.3.4") != 0) {
            printf("   Expected: 1.2.3.4, Got: %s\n", result);
        }
        free(result);
    }

    /*
     * Test case 7: 8.8.8.8 (Google DNS)
     */
    result = ipv4_string(0x08080808);
    test_cond("8.8.8.8 (symmetric address)",
        result != NULL && strcmp(result, "8.8.8.8") == 0);
    if (result) {
        if (strcmp(result, "8.8.8.8") != 0) {
            printf("   Expected: 8.8.8.8, Got: %s\n", result);
        }
        free(result);
    }
}

int main(void) {
    printf("BGPSee bgp_print.c Tests\n");
    printf("========================\n");

    test_ipv4_string_host_order();

    test_report();
}
