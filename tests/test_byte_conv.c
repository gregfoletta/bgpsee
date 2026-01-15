/*
 * Tests for byte conversion functions in byte_conv.h
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testhelp.h"
#include "../src/byte_conv.h"

void test_uint8_read(void) {
    test_section("uint8 read functions");

    unsigned char buf[1] = {0x42};
    unsigned char *ptr = buf;

    test_cond("uchar_to_uint8 reads 0x42",
        uchar_to_uint8(buf) == 0x42);

    test_cond("uchar_to_uint8_inc reads 0x42",
        uchar_to_uint8_inc(&ptr) == 0x42);

    test_cond("uchar_to_uint8_inc increments pointer",
        ptr == buf + 1);

    // Edge cases
    unsigned char zero[1] = {0x00};
    unsigned char max[1] = {0xFF};

    test_cond("uchar_to_uint8 reads 0x00",
        uchar_to_uint8(zero) == 0x00);

    test_cond("uchar_to_uint8 reads 0xFF",
        uchar_to_uint8(max) == 0xFF);
}

void test_uint8_write(void) {
    test_section("uint8 write functions");

    unsigned char buf[1] = {0};
    unsigned char *ptr = buf;

    uint8_to_uchar(buf, 0x42);
    test_cond("uint8_to_uchar writes 0x42",
        buf[0] == 0x42);

    buf[0] = 0;
    ptr = buf;
    uint8_to_uchar_inc(&ptr, 0x99);
    test_cond("uint8_to_uchar_inc writes 0x99",
        buf[0] == 0x99);
    test_cond("uint8_to_uchar_inc increments pointer",
        ptr == buf + 1);
}

void test_uint16_read(void) {
    test_section("uint16 big-endian read functions");

    // Big-endian: 0x1234 stored as [0x12, 0x34]
    unsigned char buf[2] = {0x12, 0x34};
    unsigned char *ptr = buf;

    test_cond("uchar_be_to_uint16 reads 0x1234",
        uchar_be_to_uint16(buf) == 0x1234);

    test_cond("uchar_be_to_uint16_inc reads 0x1234",
        uchar_be_to_uint16_inc(&ptr) == 0x1234);

    test_cond("uchar_be_to_uint16_inc increments pointer by 2",
        ptr == buf + 2);

    // Edge cases
    unsigned char zero[2] = {0x00, 0x00};
    unsigned char max[2] = {0xFF, 0xFF};
    unsigned char one[2] = {0x00, 0x01};

    test_cond("uchar_be_to_uint16 reads 0x0000",
        uchar_be_to_uint16(zero) == 0x0000);

    test_cond("uchar_be_to_uint16 reads 0xFFFF",
        uchar_be_to_uint16(max) == 0xFFFF);

    test_cond("uchar_be_to_uint16 reads 0x0001",
        uchar_be_to_uint16(one) == 0x0001);
}

void test_uint16_write(void) {
    test_section("uint16 big-endian write functions");

    unsigned char buf[2] = {0};
    unsigned char *ptr = buf;

    uint16_to_uchar_be(buf, 0x1234);
    test_cond("uint16_to_uchar_be writes 0x12 first (big-endian)",
        buf[0] == 0x12);
    test_cond("uint16_to_uchar_be writes 0x34 second",
        buf[1] == 0x34);

    memset(buf, 0, 2);
    ptr = buf;
    uint16_to_uchar_be_inc(&ptr, 0xABCD);
    test_cond("uint16_to_uchar_be_inc writes correctly",
        buf[0] == 0xAB && buf[1] == 0xCD);
    test_cond("uint16_to_uchar_be_inc increments pointer by 2",
        ptr == buf + 2);
}

void test_uint32_read(void) {
    test_section("uint32 big-endian read functions");

    // Big-endian: 0x12345678 stored as [0x12, 0x34, 0x56, 0x78]
    unsigned char buf[4] = {0x12, 0x34, 0x56, 0x78};
    unsigned char *ptr = buf;

    uint32_t result = uchar_be_to_uint32(buf);
    test_cond("uchar_be_to_uint32 reads 0x12345678",
        result == 0x12345678);

    ptr = buf;
    result = uchar_be_to_uint32_inc(&ptr);
    test_cond("uchar_be_to_uint32_inc reads 0x12345678",
        result == 0x12345678);

    test_cond("uchar_be_to_uint32_inc increments pointer by 4",
        ptr == buf + 4);

    // Edge cases
    unsigned char zero[4] = {0x00, 0x00, 0x00, 0x00};
    unsigned char max[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    unsigned char one[4] = {0x00, 0x00, 0x00, 0x01};

    test_cond("uchar_be_to_uint32 reads 0x00000000",
        uchar_be_to_uint32(zero) == 0x00000000);

    test_cond("uchar_be_to_uint32 reads 0xFFFFFFFF",
        uchar_be_to_uint32(max) == 0xFFFFFFFF);

    test_cond("uchar_be_to_uint32 reads 0x00000001",
        uchar_be_to_uint32(one) == 0x00000001);
}

void test_uint32_write(void) {
    test_section("uint32 big-endian write functions");

    unsigned char buf[4] = {0};
    unsigned char *ptr = buf;

    uint32_to_uchar_be(buf, 0x12345678);
    test_cond("uint32_to_uchar_be writes 0x12 first (big-endian)",
        buf[0] == 0x12);
    test_cond("uint32_to_uchar_be writes 0x34 second",
        buf[1] == 0x34);
    test_cond("uint32_to_uchar_be writes 0x56 third",
        buf[2] == 0x56);
    test_cond("uint32_to_uchar_be writes 0x78 fourth",
        buf[3] == 0x78);

    memset(buf, 0, 4);
    ptr = buf;
    uint32_to_uchar_be_inc(&ptr, 0xDEADBEEF);
    test_cond("uint32_to_uchar_be_inc writes correctly",
        buf[0] == 0xDE && buf[1] == 0xAD && buf[2] == 0xBE && buf[3] == 0xEF);
    test_cond("uint32_to_uchar_be_inc increments pointer by 4",
        ptr == buf + 4);
}

void test_uint32_roundtrip(void) {
    test_section("uint32 round-trip (write then read)");

    unsigned char buf[4] = {0};
    uint32_t original = 0x12345678;

    uint32_to_uchar_be(buf, original);
    uint32_t result = uchar_be_to_uint32(buf);

    test_cond("uint32 round-trip preserves value",
        result == original);

    // Test with IP address (common use case)
    original = 0xC0A80101;  // 192.168.1.1
    uint32_to_uchar_be(buf, original);
    result = uchar_be_to_uint32(buf);

    test_cond("uint32 round-trip preserves IP address",
        result == original);
}

void test_uint64_write(void) {
    test_section("uint64 big-endian write functions");

    unsigned char buf[8] = {0};

    uint64_to_uchar_be(buf, 0x0102030405060708ULL);
    test_cond("uint64_to_uchar_be writes byte 0 correctly",
        buf[0] == 0x01);
    test_cond("uint64_to_uchar_be writes byte 1 correctly",
        buf[1] == 0x02);
    test_cond("uint64_to_uchar_be writes byte 2 correctly",
        buf[2] == 0x03);
    test_cond("uint64_to_uchar_be writes byte 3 correctly",
        buf[3] == 0x04);
    test_cond("uint64_to_uchar_be writes byte 4 correctly",
        buf[4] == 0x05);
    test_cond("uint64_to_uchar_be writes byte 5 correctly",
        buf[5] == 0x06);
    test_cond("uint64_to_uchar_be writes byte 6 correctly",
        buf[6] == 0x07);
    test_cond("uint64_to_uchar_be writes byte 7 correctly",
        buf[7] == 0x08);
}

void test_uint64_read(void) {
    test_section("uint64 big-endian read functions");

    // Big-endian: 0x0102030405060708 stored as [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    unsigned char buf[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    uint64_t result = uchar_be_to_uint64(buf);
    test_cond("uchar_be_to_uint64 reads 0x0102030405060708",
        result == 0x0102030405060708ULL);
}

void test_uint64_roundtrip(void) {
    test_section("uint64 round-trip (write then read)");

    unsigned char buf[8] = {0};
    uint64_t original = 0x0102030405060708ULL;

    uint64_to_uchar_be(buf, original);
    uint64_t result = uchar_be_to_uint64(buf);

    test_cond("uint64 round-trip preserves value",
        result == original);
}

int main(void) {
    printf("BGPSee Byte Conversion Tests\n");
    printf("============================\n");

    test_uint8_read();
    test_uint8_write();
    test_uint16_read();
    test_uint16_write();
    test_uint32_read();
    test_uint32_write();
    test_uint32_roundtrip();
    test_uint64_write();
    test_uint64_read();
    test_uint64_roundtrip();

    test_report();
}
