/*
 * Minimal testing framework for BGPSee
 * Based on Redis testhelp.h by Salvatore Sanfilippo
 */

#ifndef __TESTHELP_H
#define __TESTHELP_H

#include <stdio.h>
#include <stdlib.h>

static int __failed_tests = 0;
static int __test_num = 0;

#define test_cond(descr, _c) do { \
    __test_num++; \
    printf("%d - %s: ", __test_num, descr); \
    if(_c) { \
        printf("PASSED\n"); \
    } else { \
        printf("FAILED\n"); \
        __failed_tests++; \
    } \
} while(0)

#define test_report() do { \
    printf("\n%d tests, %d passed, %d failed\n", __test_num, \
                    __test_num-__failed_tests, __failed_tests); \
    if (__failed_tests) { \
        printf("=== WARNING === We have failed tests here...\n"); \
        return 1; \
    } \
    return 0; \
} while(0)

#define test_section(name) do { \
    printf("\n=== %s ===\n", name); \
} while(0)

#endif
