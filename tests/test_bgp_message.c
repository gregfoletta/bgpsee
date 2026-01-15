/*
 * Tests for BGP message parsing functions
 *
 * These tests use socketpair() to feed raw BGP message data to recv_msg()
 * and verify the parsed results.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>

#include "testhelp.h"
#include "../src/bgp_message.h"
#include "../src/list.h"

/*
 * Helper function to create a socket pair and write test data
 * Returns the read end of the socket pair, or -1 on error
 */
int create_test_socket(const unsigned char *data, size_t len) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        return -1;
    }

    // Write test data to write end
    if (write(fds[1], data, len) != (ssize_t)len) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    // Close write end so recv gets EOF after data
    close(fds[1]);

    return fds[0];
}

/*
 * Helper to construct BGP header
 * Returns number of bytes written (always 19)
 */
int make_bgp_header(unsigned char *buf, uint16_t length, uint8_t type) {
    // 16 bytes of 0xFF marker
    memset(buf, 0xFF, 16);
    // Length (big-endian)
    buf[16] = (uint8_t)(length >> 8);
    buf[17] = (uint8_t)(length & 0xFF);
    // Type
    buf[18] = type;
    return 19;
}

void test_keepalive_message(void) {
    test_section("KEEPALIVE message parsing");

    // KEEPALIVE is just a header with type=4 and length=19
    unsigned char msg[19];
    make_bgp_header(msg, 19, KEEPALIVE);

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for KEEPALIVE", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns non-NULL for valid KEEPALIVE",
            parsed != NULL);

        if (parsed) {
            test_cond("KEEPALIVE type is correct",
                parsed->type == KEEPALIVE);
            test_cond("KEEPALIVE length is 19",
                parsed->length == 19);
            test_cond("KEEPALIVE body_length is 0",
                parsed->body_length == 0);

            free_msg(parsed);
        }
    }
}

void test_open_message(void) {
    test_section("OPEN message parsing");

    // Minimal OPEN message: header (19) + version(1) + ASN(2) + hold_time(2) + router_id(4) + opt_param_len(1) = 29 bytes
    unsigned char msg[29];
    int offset = make_bgp_header(msg, 29, OPEN);

    // OPEN body
    msg[offset++] = 4;              // Version = 4
    msg[offset++] = 0x00;           // ASN high byte
    msg[offset++] = 0x01;           // ASN low byte (ASN = 1)
    msg[offset++] = 0x00;           // Hold time high byte
    msg[offset++] = 0xB4;           // Hold time low byte (180 seconds)
    msg[offset++] = 0x0A;           // Router ID byte 1 (10.0.0.1)
    msg[offset++] = 0x00;           // Router ID byte 2
    msg[offset++] = 0x00;           // Router ID byte 3
    msg[offset++] = 0x01;           // Router ID byte 4
    msg[offset++] = 0x00;           // Optional parameters length = 0

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for OPEN", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns non-NULL for valid OPEN",
            parsed != NULL);

        if (parsed) {
            test_cond("OPEN type is correct",
                parsed->type == OPEN);
            test_cond("OPEN length is 29",
                parsed->length == 29);
            test_cond("OPEN version is 4",
                parsed->open.version == 4);
            test_cond("OPEN ASN is 1",
                parsed->open.asn == 1);
            test_cond("OPEN hold_time is 180",
                parsed->open.hold_time == 180);
            test_cond("OPEN opt_param_len is 0",
                parsed->open.opt_param_len == 0);

            free_msg(parsed);
        }
    }
}

void test_notification_message(void) {
    test_section("NOTIFICATION message parsing");

    // NOTIFICATION: header (19) + code(1) + subcode(1) = 21 bytes minimum
    unsigned char msg[21];
    int offset = make_bgp_header(msg, 21, NOTIFICATION);

    msg[offset++] = 6;    // Error code 6 = Cease
    msg[offset++] = 4;    // Subcode 4 = Administrative Reset

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for NOTIFICATION", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns non-NULL for valid NOTIFICATION",
            parsed != NULL);

        if (parsed) {
            test_cond("NOTIFICATION type is correct",
                parsed->type == NOTIFICATION);
            test_cond("NOTIFICATION code is 6 (Cease)",
                parsed->notification.code == 6);
            test_cond("NOTIFICATION subcode is 4 (Administrative Reset)",
                parsed->notification.subcode == 4);

            free_msg(parsed);
        }
    }
}

void test_update_empty(void) {
    test_section("UPDATE message parsing (empty)");

    // Minimal UPDATE: header (19) + withdrawn_len(2) + path_attr_len(2) = 23 bytes
    unsigned char msg[23];
    int offset = make_bgp_header(msg, 23, UPDATE);

    msg[offset++] = 0x00;    // Withdrawn routes length high
    msg[offset++] = 0x00;    // Withdrawn routes length low (0)
    msg[offset++] = 0x00;    // Path attributes length high
    msg[offset++] = 0x00;    // Path attributes length low (0)

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for empty UPDATE", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns non-NULL for empty UPDATE",
            parsed != NULL);

        if (parsed) {
            test_cond("UPDATE type is correct",
                parsed->type == UPDATE);
            test_cond("UPDATE withdrawn_route_length is 0",
                parsed->update->withdrawn_route_length == 0);
            test_cond("UPDATE path_attr_length is 0",
                parsed->update->path_attr_length == 0);

            free_msg(parsed);
        }
    }
}

void test_update_with_nlri(void) {
    test_section("UPDATE message parsing (with NLRI)");

    // UPDATE with one /24 NLRI and minimal attributes (ORIGIN, AS_PATH, NEXT_HOP)
    // NLRI: 192.168.1.0/24 = length(1) + 3 bytes = 4 bytes
    // ORIGIN: flags(1) + type(1) + len(1) + value(1) = 4 bytes
    // AS_PATH: flags(1) + type(1) + len(1) + seg_type(1) + seg_len(1) + AS(2) = 7 bytes
    // NEXT_HOP: flags(1) + type(1) + len(1) + value(4) = 7 bytes
    // Total path attrs = 18 bytes
    // Total: 19 (header) + 2 (withdrawn_len=0) + 2 (pa_len=18) + 18 (pa) + 4 (nlri) = 45 bytes

    unsigned char msg[45];
    int offset = make_bgp_header(msg, 45, UPDATE);

    // Withdrawn routes length = 0
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    // Path attributes length = 18
    msg[offset++] = 0x00;
    msg[offset++] = 0x12;  // 18

    // ORIGIN attribute (type 1): IGP
    msg[offset++] = 0x40;  // Flags: Well-known, Transitive
    msg[offset++] = 0x01;  // Type: ORIGIN
    msg[offset++] = 0x01;  // Length: 1
    msg[offset++] = 0x00;  // Value: IGP

    // AS_PATH attribute (type 2): AS_SEQUENCE with one AS (65001)
    msg[offset++] = 0x40;  // Flags: Well-known, Transitive
    msg[offset++] = 0x02;  // Type: AS_PATH
    msg[offset++] = 0x04;  // Length: 4
    msg[offset++] = 0x02;  // Segment type: AS_SEQUENCE
    msg[offset++] = 0x01;  // Segment length: 1 AS
    msg[offset++] = 0xFD;  // AS high byte (65001 = 0xFDE9)
    msg[offset++] = 0xE9;  // AS low byte

    // NEXT_HOP attribute (type 3): 10.0.0.1
    msg[offset++] = 0x40;  // Flags: Well-known, Transitive
    msg[offset++] = 0x03;  // Type: NEXT_HOP
    msg[offset++] = 0x04;  // Length: 4
    msg[offset++] = 0x0A;  // 10.
    msg[offset++] = 0x00;  // 0.
    msg[offset++] = 0x00;  // 0.
    msg[offset++] = 0x01;  // 1

    // NLRI: 192.168.1.0/24
    msg[offset++] = 0x18;  // Length: 24 bits
    msg[offset++] = 0xC0;  // 192.
    msg[offset++] = 0xA8;  // 168.
    msg[offset++] = 0x01;  // 1.

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for UPDATE with NLRI", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns non-NULL for UPDATE with NLRI",
            parsed != NULL);

        if (parsed) {
            test_cond("UPDATE type is correct",
                parsed->type == UPDATE);
            test_cond("UPDATE path_attr_length is 18",
                parsed->update->path_attr_length == 18);

            // Check ORIGIN attribute
            test_cond("ORIGIN attribute exists",
                parsed->update->path_attrs[ORIGIN] != NULL);
            if (parsed->update->path_attrs[ORIGIN]) {
                test_cond("ORIGIN is IGP (0)",
                    parsed->update->path_attrs[ORIGIN]->origin == 0);
            }

            // Check AS_PATH attribute
            test_cond("AS_PATH attribute exists",
                parsed->update->path_attrs[AS_PATH] != NULL);
            if (parsed->update->path_attrs[AS_PATH] &&
                parsed->update->path_attrs[AS_PATH]->as_path) {
                test_cond("AS_PATH has 1 segment",
                    parsed->update->path_attrs[AS_PATH]->as_path->n_segments == 1);
            }

            // Check NEXT_HOP attribute
            test_cond("NEXT_HOP attribute exists",
                parsed->update->path_attrs[NEXT_HOP] != NULL);

            // Check NLRI
            test_cond("NLRI list is not empty",
                !list_empty(&parsed->update->nlri));

            if (!list_empty(&parsed->update->nlri)) {
                struct ipv4_nlri *nlri = list_entry(
                    parsed->update->nlri.next,
                    struct ipv4_nlri, list);
                test_cond("NLRI prefix length is 24",
                    nlri->length == 24);
                test_cond("NLRI prefix is 192.168.1.x",
                    nlri->prefix[0] == 192 &&
                    nlri->prefix[1] == 168 &&
                    nlri->prefix[2] == 1);
            }

            free_msg(parsed);
        }
    }
}

void test_update_with_withdrawn(void) {
    test_section("UPDATE message parsing (with withdrawn routes)");

    // UPDATE with one withdrawn route: 10.0.0.0/8
    // Withdrawn: length(1) + 1 byte = 2 bytes
    // Total: 19 (header) + 2 (withdrawn_len=2) + 2 (withdrawn) + 2 (pa_len=0) = 25 bytes

    unsigned char msg[25];
    int offset = make_bgp_header(msg, 25, UPDATE);

    // Withdrawn routes length = 2
    msg[offset++] = 0x00;
    msg[offset++] = 0x02;

    // Withdrawn route: 10.0.0.0/8
    msg[offset++] = 0x08;  // Length: 8 bits
    msg[offset++] = 0x0A;  // 10.

    // Path attributes length = 0
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for UPDATE with withdrawn", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns non-NULL for UPDATE with withdrawn",
            parsed != NULL);

        if (parsed) {
            test_cond("UPDATE withdrawn_route_length is 2",
                parsed->update->withdrawn_route_length == 2);

            test_cond("Withdrawn routes list is not empty",
                !list_empty(&parsed->update->withdrawn_routes));

            if (!list_empty(&parsed->update->withdrawn_routes)) {
                struct ipv4_nlri *nlri = list_entry(
                    parsed->update->withdrawn_routes.next,
                    struct ipv4_nlri, list);
                test_cond("Withdrawn prefix length is 8",
                    nlri->length == 8);
                test_cond("Withdrawn prefix is 10.x.x.x",
                    nlri->prefix[0] == 10);
            }

            free_msg(parsed);
        }
    }
}

void test_invalid_header_marker(void) {
    test_section("Invalid header marker");

    // Header with wrong marker
    unsigned char msg[19];
    memset(msg, 0x00, 16);  // Wrong marker (should be 0xFF)
    msg[16] = 0x00;
    msg[17] = 0x13;  // Length = 19
    msg[18] = KEEPALIVE;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for invalid marker", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns NULL for invalid marker",
            parsed == NULL);
    }
}

void test_invalid_message_type(void) {
    test_section("Invalid message type");

    // Header with invalid type (0)
    unsigned char msg[19];
    make_bgp_header(msg, 19, 0);  // Type 0 is invalid

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for invalid type 0", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns NULL for type 0",
            parsed == NULL);
    }

    // Type 6 is also invalid
    make_bgp_header(msg, 19, 6);

    fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for invalid type 6", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns NULL for type 6",
            parsed == NULL);
    }
}

void test_update_invalid_withdrawn_length(void) {
    test_section("UPDATE with invalid withdrawn length");

    // UPDATE claiming more withdrawn data than available
    unsigned char msg[23];
    int offset = make_bgp_header(msg, 23, UPDATE);

    // Withdrawn routes length = 100 (but body only has 4 bytes total)
    msg[offset++] = 0x00;
    msg[offset++] = 0x64;  // 100

    // Path attributes length (won't be read due to error)
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for invalid withdrawn length", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        test_cond("recv_msg returns NULL for invalid withdrawn length",
            parsed == NULL);
    }
}

void test_send_notification(void) {
    test_section("send_notification function");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        test_cond("Created socket pair for send_notification", 0);
        return;
    }
    test_cond("Created socket pair for send_notification", 1);

    // Send a CEASE/Administrative Shutdown notification
    ssize_t sent = send_notification(fds[1], BGP_ERR_CEASE, BGP_ERR_CEASE_ADMIN_SHUT);
    test_cond("send_notification returns 21 bytes", sent == 21);

    // Read and verify the message
    unsigned char buf[21];
    ssize_t received = recv(fds[0], buf, sizeof(buf), MSG_WAITALL);
    test_cond("Received 21 bytes", received == 21);

    // Verify marker (16 bytes of 0xFF)
    int marker_ok = 1;
    for (int i = 0; i < 16; i++) {
        if (buf[i] != 0xFF) {
            marker_ok = 0;
            break;
        }
    }
    test_cond("NOTIFICATION marker is correct", marker_ok);

    // Verify length (bytes 16-17, big-endian)
    uint16_t length = ((uint16_t)buf[16] << 8) | buf[17];
    test_cond("NOTIFICATION length is 21", length == 21);

    // Verify type (byte 18)
    test_cond("NOTIFICATION type is 3", buf[18] == NOTIFICATION);

    // Verify error code (byte 19)
    test_cond("NOTIFICATION error code is 6 (CEASE)", buf[19] == BGP_ERR_CEASE);

    // Verify subcode (byte 20)
    test_cond("NOTIFICATION subcode is 2 (ADMIN_SHUT)", buf[20] == BGP_ERR_CEASE_ADMIN_SHUT);

    close(fds[0]);
    close(fds[1]);
}

void test_send_notification_hold_timer(void) {
    test_section("send_notification for Hold Timer Expired");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        test_cond("Created socket pair", 0);
        return;
    }
    test_cond("Created socket pair", 1);

    // Send Hold Timer Expired notification
    ssize_t sent = send_notification(fds[1], BGP_ERR_HOLD_TIMER, 0);
    test_cond("send_notification returns 21 bytes", sent == 21);

    unsigned char buf[21];
    recv(fds[0], buf, sizeof(buf), MSG_WAITALL);

    test_cond("Error code is 4 (Hold Timer Expired)", buf[19] == BGP_ERR_HOLD_TIMER);
    test_cond("Subcode is 0", buf[20] == 0);

    close(fds[0]);
    close(fds[1]);
}

void test_send_notification_bad_peer_as(void) {
    test_section("send_notification for Bad Peer AS");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        test_cond("Created socket pair", 0);
        return;
    }
    test_cond("Created socket pair", 1);

    // Send OPEN error - Bad Peer AS
    ssize_t sent = send_notification(fds[1], BGP_ERR_OPEN, BGP_ERR_OPEN_PEER_AS);
    test_cond("send_notification returns 21 bytes", sent == 21);

    unsigned char buf[21];
    recv(fds[0], buf, sizeof(buf), MSG_WAITALL);

    test_cond("Error code is 2 (OPEN Message Error)", buf[19] == BGP_ERR_OPEN);
    test_cond("Subcode is 2 (Bad Peer AS)", buf[20] == BGP_ERR_OPEN_PEER_AS);

    close(fds[0]);
    close(fds[1]);
}

void test_notification_round_trip(void) {
    test_section("NOTIFICATION send and parse round trip");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        test_cond("Created socket pair", 0);
        return;
    }
    test_cond("Created socket pair", 1);

    // Send a NOTIFICATION
    send_notification(fds[1], BGP_ERR_CEASE, BGP_ERR_CEASE_PEER_DECONF);
    close(fds[1]);  // Close write end so recv_msg gets EOF after data

    // Parse it with recv_msg
    struct bgp_msg *parsed = recv_msg(fds[0]);
    close(fds[0]);

    test_cond("recv_msg parses sent NOTIFICATION", parsed != NULL);

    if (parsed) {
        test_cond("Parsed type is NOTIFICATION", parsed->type == NOTIFICATION);
        test_cond("Parsed error code is CEASE", parsed->notification.code == BGP_ERR_CEASE);
        test_cond("Parsed subcode is PEER_DECONF", parsed->notification.subcode == BGP_ERR_CEASE_PEER_DECONF);
        free_msg(parsed);
    }
}

void test_nlri_invalid_prefix_length(void) {
    test_section("UPDATE with invalid NLRI prefix length");

    // UPDATE with NLRI claiming prefix length > 32 (invalid for IPv4)
    unsigned char msg[28];
    int offset = make_bgp_header(msg, 28, UPDATE);

    // Withdrawn routes length = 0
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    // Path attributes length = 0
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    // NLRI with invalid prefix length (40 bits > 32)
    msg[offset++] = 0x28;  // Length: 40 bits (invalid!)
    msg[offset++] = 0xC0;  // 192.
    msg[offset++] = 0xA8;  // 168.
    msg[offset++] = 0x01;  // 1.
    msg[offset++] = 0x00;  // 0.

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for invalid NLRI prefix length", fd >= 0);

    if (fd >= 0) {
        struct bgp_msg *parsed = recv_msg(fd);
        close(fd);

        // The UPDATE should parse but skip the invalid NLRI
        // (our fix returns NULL from parse_ipv4_nlri, which breaks the loop)
        test_cond("UPDATE with invalid NLRI prefix handled",
            parsed != NULL);

        if (parsed) {
            // The invalid NLRI should have been skipped
            test_cond("NLRI list is empty (invalid NLRI skipped)",
                list_empty(&parsed->update->nlri));
            free_msg(parsed);
        }
    }
}

int main(void) {
    printf("BGPSee Message Parsing Tests\n");
    printf("============================\n");

    // Valid message tests
    test_keepalive_message();
    test_open_message();
    test_notification_message();
    test_update_empty();
    test_update_with_nlri();
    test_update_with_withdrawn();

    // Invalid message tests (security-relevant)
    test_invalid_header_marker();
    test_invalid_message_type();
    test_update_invalid_withdrawn_length();
    test_nlri_invalid_prefix_length();

    // NOTIFICATION send tests
    test_send_notification();
    test_send_notification_hold_timer();
    test_send_notification_bad_peer_as();
    test_notification_round_trip();

    test_report();
}
