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
#include "../src/bgp_capability.h"
#include "../src/bgp_peer.h"
#include "../src/list.h"

/*
 * Helper to create a minimal peer struct for testing.
 * Sets socket.fd and four_octet_asn, caller must free.
 */
static struct bgp_peer *create_test_peer(int fd, int four_octet_asn) {
    struct bgp_peer *peer = calloc(1, sizeof(*peer));
    if (peer) {
        peer->socket.fd = fd;
        peer->four_octet_asn = four_octet_asn;
    }
    return peer;
}

static void free_test_peer(struct bgp_peer *peer) {
    free(peer);
}

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns NULL for type 0",
            parsed == NULL);
    }

    // Type 6 is also invalid
    make_bgp_header(msg, 19, 6);

    fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for invalid type 6", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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
    struct bgp_peer *test_peer = create_test_peer(fds[0], 0);
    struct bgp_msg *parsed = recv_msg(test_peer);
    close(fds[0]);
    free_test_peer(test_peer);

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
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

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

void test_capabilities_create_free(void) {
    test_section("Capabilities create and free");

    struct bgp_capabilities *caps = bgp_capabilities_create();
    test_cond("bgp_capabilities_create returns non-NULL", caps != NULL);

    if (caps) {
        test_cond("Initial count is 0", caps->count == 0);
        test_cond("Initial total_length is 0", caps->total_length == 0);
        bgp_capabilities_free(caps);
    }

    /* Test freeing NULL (should not crash) */
    bgp_capabilities_free(NULL);
    test_cond("bgp_capabilities_free(NULL) doesn't crash", 1);
}

void test_capabilities_add_route_refresh(void) {
    test_section("Capabilities add route refresh");

    struct bgp_capabilities *caps = bgp_capabilities_create();
    test_cond("Created capabilities", caps != NULL);

    if (caps) {
        int ret = bgp_capabilities_add_route_refresh(caps);
        test_cond("add_route_refresh returns 0", ret == 0);
        test_cond("count is 1", caps->count == 1);
        /* Route refresh: code(1) + length(1) + value(0) = 2 bytes */
        test_cond("total_length is 2", caps->total_length == 2);

        bgp_capabilities_free(caps);
    }
}

void test_capabilities_add_mp_ext(void) {
    test_section("Capabilities add multiprotocol extensions");

    struct bgp_capabilities *caps = bgp_capabilities_create();
    test_cond("Created capabilities", caps != NULL);

    if (caps) {
        int ret = bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV4, BGP_SAFI_UNICAST);
        test_cond("add_mp_ext IPv4 returns 0", ret == 0);
        test_cond("count is 1", caps->count == 1);
        /* MP ext: code(1) + length(1) + AFI(2) + reserved(1) + SAFI(1) = 6 bytes */
        test_cond("total_length is 6", caps->total_length == 6);

        ret = bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV6, BGP_SAFI_UNICAST);
        test_cond("add_mp_ext IPv6 returns 0", ret == 0);
        test_cond("count is 2", caps->count == 2);
        test_cond("total_length is 12", caps->total_length == 12);

        bgp_capabilities_free(caps);
    }
}

void test_capabilities_add_four_octet_asn(void) {
    test_section("Capabilities add 4-octet ASN");

    struct bgp_capabilities *caps = bgp_capabilities_create();
    test_cond("Created capabilities", caps != NULL);

    if (caps) {
        int ret = bgp_capabilities_add_four_octet_asn(caps, 65001);
        test_cond("add_four_octet_asn returns 0", ret == 0);
        test_cond("count is 1", caps->count == 1);
        /* 4-octet ASN: code(1) + length(1) + ASN(4) = 6 bytes */
        test_cond("total_length is 6", caps->total_length == 6);

        bgp_capabilities_free(caps);
    }
}

void test_capabilities_encode(void) {
    test_section("Capabilities encode");

    struct bgp_capabilities *caps = bgp_capabilities_create();
    test_cond("Created capabilities", caps != NULL);

    if (caps) {
        unsigned char buf[256];

        /* Empty capabilities */
        int len = bgp_capabilities_encode(caps, buf, sizeof(buf));
        test_cond("Empty caps encode returns 0", len == 0);

        /* Add route refresh */
        bgp_capabilities_add_route_refresh(caps);
        len = bgp_capabilities_encode(caps, buf, sizeof(buf));
        /* param_type(1) + param_len(1) + cap_code(1) + cap_len(1) = 4 bytes */
        test_cond("Route refresh encode returns 4", len == 4);

        /* Verify encoded data */
        test_cond("Param type is 2 (capabilities)", buf[0] == 2);
        test_cond("Param length is 2", buf[1] == 2);
        test_cond("Cap code is 2 (route refresh)", buf[2] == BGP_CAP_ROUTE_REFRESH);
        test_cond("Cap length is 0", buf[3] == 0);

        bgp_capabilities_free(caps);
    }
}

void test_capabilities_encode_multiple(void) {
    test_section("Capabilities encode multiple");

    struct bgp_capabilities *caps = bgp_capabilities_create();
    test_cond("Created capabilities", caps != NULL);

    if (caps) {
        unsigned char buf[256];

        bgp_capabilities_add_route_refresh(caps);
        bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV4, BGP_SAFI_UNICAST);
        bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV6, BGP_SAFI_UNICAST);

        int len = bgp_capabilities_encode(caps, buf, sizeof(buf));
        /* param_type(1) + param_len(1) + (route_refresh: 2) + (mp_ext: 6) + (mp_ext: 6) = 16 */
        test_cond("Multiple caps encode returns 16", len == 16);

        /* Verify param header */
        test_cond("Param type is 2", buf[0] == 2);
        test_cond("Param length is 14", buf[1] == 14);

        /* Route refresh at offset 2 */
        test_cond("First cap is route refresh", buf[2] == BGP_CAP_ROUTE_REFRESH);

        /* IPv4 MP ext at offset 4 */
        test_cond("Second cap is MP ext", buf[4] == BGP_CAP_MP_EXT);
        test_cond("Second cap length is 4", buf[5] == 4);
        /* AFI is big-endian: 0x00 0x01 for IPv4 */
        test_cond("AFI high byte is 0", buf[6] == 0);
        test_cond("AFI low byte is 1 (IPv4)", buf[7] == 1);
        test_cond("Reserved byte is 0", buf[8] == 0);
        test_cond("SAFI is 1 (unicast)", buf[9] == 1);

        /* IPv6 MP ext at offset 10 */
        test_cond("Third cap is MP ext", buf[10] == BGP_CAP_MP_EXT);
        test_cond("AFI for third cap is 2 (IPv6)", buf[13] == 2);

        bgp_capabilities_free(caps);
    }
}

void test_send_open_no_caps(void) {
    test_section("send_open without capabilities");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        test_cond("Created socket pair", 0);
        return;
    }
    test_cond("Created socket pair", 1);

    /* Send OPEN with no capabilities */
    ssize_t sent = send_open(fds[1], 4, 65001, 180, 0x0A000001, NULL);
    test_cond("send_open returns 29 bytes (no caps)", sent == 29);

    unsigned char buf[64];
    ssize_t received = recv(fds[0], buf, sizeof(buf), 0);
    test_cond("Received 29 bytes", received == 29);

    /* Verify opt_param_len is 0 */
    test_cond("opt_param_len is 0", buf[28] == 0);

    close(fds[0]);
    close(fds[1]);
}

void test_send_open_with_caps(void) {
    test_section("send_open with capabilities");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        test_cond("Created socket pair", 0);
        return;
    }
    test_cond("Created socket pair", 1);

    struct bgp_capabilities *caps = bgp_capabilities_create();
    test_cond("Created capabilities", caps != NULL);

    if (caps) {
        bgp_capabilities_add_route_refresh(caps);
        bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV4, BGP_SAFI_UNICAST);

        /* 29 (base OPEN) + 2 (param header) + 2 (route refresh) + 6 (mp ext) = 39 */
        ssize_t sent = send_open(fds[1], 4, 65001, 180, 0x0A000001, caps);
        test_cond("send_open returns 39 bytes", sent == 39);

        unsigned char buf[64];
        ssize_t received = recv(fds[0], buf, sizeof(buf), 0);
        test_cond("Received 39 bytes", received == 39);

        /* Verify BGP header */
        int marker_ok = 1;
        for (int i = 0; i < 16; i++) {
            if (buf[i] != 0xFF) marker_ok = 0;
        }
        test_cond("Marker is correct", marker_ok);

        uint16_t length = ((uint16_t)buf[16] << 8) | buf[17];
        test_cond("Length in header is 39", length == 39);

        test_cond("Type is OPEN (1)", buf[18] == OPEN);

        /* Verify OPEN fields */
        test_cond("Version is 4", buf[19] == 4);

        uint16_t asn = ((uint16_t)buf[20] << 8) | buf[21];
        test_cond("ASN is 65001", asn == 65001);

        uint16_t hold_time = ((uint16_t)buf[22] << 8) | buf[23];
        test_cond("Hold time is 180", hold_time == 180);

        /* opt_param_len: 2 (param header) + 2 (route refresh) + 6 (mp ext) = 10 */
        test_cond("opt_param_len is 10", buf[28] == 10);

        /* Verify capabilities parameter */
        test_cond("Param type is 2 (capabilities)", buf[29] == 2);
        test_cond("Param length is 8", buf[30] == 8);

        /* Route refresh capability */
        test_cond("First cap code is 2 (route refresh)", buf[31] == BGP_CAP_ROUTE_REFRESH);
        test_cond("First cap length is 0", buf[32] == 0);

        /* MP extensions capability */
        test_cond("Second cap code is 1 (mp ext)", buf[33] == BGP_CAP_MP_EXT);
        test_cond("Second cap length is 4", buf[34] == 4);

        bgp_capabilities_free(caps);
    }

    close(fds[0]);
    close(fds[1]);
}

void test_send_open_round_trip(void) {
    test_section("send_open and parse round trip with capabilities");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        test_cond("Created socket pair", 0);
        return;
    }
    test_cond("Created socket pair", 1);

    struct bgp_capabilities *caps = bgp_capabilities_create();
    if (caps) {
        bgp_capabilities_add_route_refresh(caps);
        bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV6, BGP_SAFI_UNICAST);

        send_open(fds[1], 4, 65001, 90, 0xC0A80001, caps);
        close(fds[1]);

        struct bgp_peer *test_peer = create_test_peer(fds[0], 0);
        struct bgp_msg *parsed = recv_msg(test_peer);
        close(fds[0]);
        free_test_peer(test_peer);

        test_cond("recv_msg parses OPEN with caps", parsed != NULL);

        if (parsed) {
            test_cond("Type is OPEN", parsed->type == OPEN);
            test_cond("Version is 4", parsed->open.version == 4);
            test_cond("ASN is 65001", parsed->open.asn == 65001);
            test_cond("Hold time is 90", parsed->open.hold_time == 90);
            test_cond("Router ID is 0xC0A80001", parsed->open.router_id == 0xC0A80001);
            /* opt_param_len = param_header(2) + route_refresh(2) + mp_ext(6) = 10 */
            test_cond("opt_param_len is 10", parsed->open.opt_param_len == 10);

            free_msg(parsed);
        }

        bgp_capabilities_free(caps);
    } else {
        close(fds[0]);
        close(fds[1]);
    }
}

void test_update_mp_reach_ipv6(void) {
    test_section("UPDATE with MP_REACH_NLRI (IPv6)");

    /*
     * UPDATE with MP_REACH_NLRI containing IPv6 prefix 2001:db8::/32
     * MP_REACH_NLRI body:
     *   AFI (2) + SAFI (1) + NH_Len (1) + Next_Hop (16) + Reserved (1) + NLRI (5)
     *   = 2 + 1 + 1 + 16 + 1 + 5 = 26 bytes
     *
     * Path attribute header (extended length): flags (1) + type (1) + length (2) = 4 bytes
     * Total path attrs = 4 + 26 = 30 bytes
     * Total: 19 (header) + 2 (withdrawn_len=0) + 2 (pa_len=30) + 30 (pa) = 53 bytes
     */

    unsigned char msg[53];
    int offset = make_bgp_header(msg, 53, UPDATE);

    /* Withdrawn routes length = 0 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    /* Path attributes length = 30 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x1E;  /* 30 */

    /* MP_REACH_NLRI attribute (type 14) */
    msg[offset++] = 0x90;  /* Flags: Optional, Transitive, Extended Length */
    msg[offset++] = 0x0E;  /* Type: MP_REACH_NLRI (14) */
    msg[offset++] = 0x00;  /* Length high byte */
    msg[offset++] = 0x1A;  /* Length low byte (26) */

    /* AFI = 2 (IPv6) */
    msg[offset++] = 0x00;
    msg[offset++] = 0x02;

    /* SAFI = 1 (Unicast) */
    msg[offset++] = 0x01;

    /* Next Hop Length = 16 */
    msg[offset++] = 0x10;

    /* Next Hop: 2001:db8::1 */
    msg[offset++] = 0x20; msg[offset++] = 0x01;  /* 2001 */
    msg[offset++] = 0x0d; msg[offset++] = 0xb8;  /* 0db8 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* 0000 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* 0000 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* 0000 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* 0000 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* 0000 */
    msg[offset++] = 0x00; msg[offset++] = 0x01;  /* 0001 */

    /* Reserved byte */
    msg[offset++] = 0x00;

    /* NLRI: 2001:db8::/32 (length=32, 4 bytes of prefix) */
    msg[offset++] = 0x20;  /* 32 bits */
    msg[offset++] = 0x20; msg[offset++] = 0x01;  /* 2001 */
    msg[offset++] = 0x0d; msg[offset++] = 0xb8;  /* 0db8 */

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for MP_REACH_NLRI IPv6", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed) {
            test_cond("UPDATE type is correct", parsed->type == UPDATE);
            test_cond("MP_REACH_NLRI attribute exists",
                parsed->update->path_attrs[MP_REACH_NLRI] != NULL);

            if (parsed->update->path_attrs[MP_REACH_NLRI]) {
                struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;
                test_cond("mp_reach pointer is not NULL", mp != NULL);

                if (mp) {
                    test_cond("AFI is 2 (IPv6)", mp->afi == 2);
                    test_cond("SAFI is 1 (Unicast)", mp->safi == 1);
                    test_cond("Next hop length is 16", mp->nh_length == 16);
                    test_cond("NLRI list is not empty", !list_empty(&mp->nlri));

                    if (!list_empty(&mp->nlri)) {
                        struct ipv6_nlri *nlri = list_entry(mp->nlri.next, struct ipv6_nlri, list);
                        test_cond("NLRI prefix length is 32", nlri->length == 32);
                        test_cond("NLRI prefix starts with 2001:0db8",
                            nlri->prefix[0] == 0x20 && nlri->prefix[1] == 0x01 &&
                            nlri->prefix[2] == 0x0d && nlri->prefix[3] == 0xb8);
                    }
                }
            }

            free_msg(parsed);
        }
    }
}

void test_update_mp_unreach_ipv6(void) {
    test_section("UPDATE with MP_UNREACH_NLRI (IPv6)");

    /*
     * UPDATE with MP_UNREACH_NLRI withdrawing 2001:db8:1::/48
     * MP_UNREACH_NLRI body:
     *   AFI (2) + SAFI (1) + Withdrawn (7) = 10 bytes
     *
     * Path attribute header (extended length): flags (1) + type (1) + length (2) = 4 bytes
     * Total path attrs = 4 + 10 = 14 bytes
     * Total: 19 (header) + 2 (withdrawn_len=0) + 2 (pa_len=14) + 14 (pa) = 37 bytes
     */

    unsigned char msg[37];
    int offset = make_bgp_header(msg, 37, UPDATE);

    /* Withdrawn routes length = 0 (IPv4 withdrawn) */
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    /* Path attributes length = 14 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x0E;  /* 14 */

    /* MP_UNREACH_NLRI attribute (type 15) */
    msg[offset++] = 0x90;  /* Flags: Optional, Transitive, Extended Length */
    msg[offset++] = 0x0F;  /* Type: MP_UNREACH_NLRI (15) */
    msg[offset++] = 0x00;  /* Length high byte */
    msg[offset++] = 0x0A;  /* Length low byte (10) */

    /* AFI = 2 (IPv6) */
    msg[offset++] = 0x00;
    msg[offset++] = 0x02;

    /* SAFI = 1 (Unicast) */
    msg[offset++] = 0x01;

    /* Withdrawn: 2001:db8:1::/48 (length=48, 6 bytes of prefix) */
    msg[offset++] = 0x30;  /* 48 bits */
    msg[offset++] = 0x20; msg[offset++] = 0x01;  /* 2001 */
    msg[offset++] = 0x0d; msg[offset++] = 0xb8;  /* 0db8 */
    msg[offset++] = 0x00; msg[offset++] = 0x01;  /* 0001 */

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for MP_UNREACH_NLRI IPv6", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed) {
            test_cond("UPDATE type is correct", parsed->type == UPDATE);
            test_cond("MP_UNREACH_NLRI attribute exists",
                parsed->update->path_attrs[MP_UNREACH_NLRI] != NULL);

            if (parsed->update->path_attrs[MP_UNREACH_NLRI]) {
                struct mp_unreach_nlri *mp = parsed->update->path_attrs[MP_UNREACH_NLRI]->mp_unreach;
                test_cond("mp_unreach pointer is not NULL", mp != NULL);

                if (mp) {
                    test_cond("AFI is 2 (IPv6)", mp->afi == 2);
                    test_cond("SAFI is 1 (Unicast)", mp->safi == 1);
                    test_cond("Withdrawn list is not empty", !list_empty(&mp->withdrawn));

                    if (!list_empty(&mp->withdrawn)) {
                        struct ipv6_nlri *nlri = list_entry(mp->withdrawn.next, struct ipv6_nlri, list);
                        test_cond("Withdrawn prefix length is 48", nlri->length == 48);
                        test_cond("Withdrawn prefix starts with 2001:0db8:0001",
                            nlri->prefix[0] == 0x20 && nlri->prefix[1] == 0x01 &&
                            nlri->prefix[2] == 0x0d && nlri->prefix[3] == 0xb8 &&
                            nlri->prefix[4] == 0x00 && nlri->prefix[5] == 0x01);
                    }
                }
            }

            free_msg(parsed);
        }
    }
}

void test_update_mp_reach_dual_nexthop(void) {
    test_section("UPDATE with MP_REACH_NLRI (dual next hop)");

    /*
     * UPDATE with MP_REACH_NLRI with global + link-local next hop (32 bytes)
     * MP_REACH_NLRI format:
     *   AFI (2) + SAFI (1) + NH_Len (1) + Next_Hop (32) + Reserved (1) + NLRI (5)
     *   = 2 + 1 + 1 + 32 + 1 + 5 = 42 bytes
     *
     * Path attribute header with extended length: flags (1) + type (1) + length (2) = 4 bytes
     * Total path attrs = 46 bytes
     * Total: 19 (header) + 2 (withdrawn_len=0) + 2 (pa_len=46) + 46 (pa) = 69 bytes
     */

    unsigned char msg[69];
    int offset = make_bgp_header(msg, 69, UPDATE);

    /* Withdrawn routes length = 0 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    /* Path attributes length = 46 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x2E;  /* 46 */

    /* MP_REACH_NLRI attribute (type 14) with extended length */
    msg[offset++] = 0x90;  /* Flags: Optional, Transitive, Extended Length */
    msg[offset++] = 0x0E;  /* Type: MP_REACH_NLRI (14) */
    msg[offset++] = 0x00;  /* Length high byte */
    msg[offset++] = 0x2A;  /* Length low byte (42) */

    /* AFI = 2 (IPv6) */
    msg[offset++] = 0x00;
    msg[offset++] = 0x02;

    /* SAFI = 1 (Unicast) */
    msg[offset++] = 0x01;

    /* Next Hop Length = 32 (global + link-local) */
    msg[offset++] = 0x20;

    /* Global Next Hop: 2001:db8::1 */
    msg[offset++] = 0x20; msg[offset++] = 0x01;
    msg[offset++] = 0x0d; msg[offset++] = 0xb8;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;

    /* Link-local Next Hop: fe80::1 */
    msg[offset++] = 0xfe; msg[offset++] = 0x80;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;

    /* Reserved byte */
    msg[offset++] = 0x00;

    /* NLRI: 2001:db8::/32 */
    msg[offset++] = 0x20;
    msg[offset++] = 0x20; msg[offset++] = 0x01;
    msg[offset++] = 0x0d; msg[offset++] = 0xb8;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for dual next hop", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_REACH_NLRI]) {
            struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;

            if (mp) {
                test_cond("Next hop length is 32", mp->nh_length == 32);
                test_cond("Global next hop starts with 2001",
                    mp->next_hop[0] == 0x20 && mp->next_hop[1] == 0x01);
                test_cond("Link-local next hop starts with fe80",
                    mp->next_hop[16] == 0xfe && mp->next_hop[17] == 0x80);
            }

            free_msg(parsed);
        } else if (parsed) {
            free_msg(parsed);
        }
    }
}

void test_evpn_type2_mac_ip(void) {
    test_section("EVPN Type 2 - MAC/IP Advertisement");

    /*
     * UPDATE with MP_REACH_NLRI containing EVPN Type 2 route:
     *   MAC aa:bb:cc:dd:ee:ff, IP 192.168.1.1, RD 10.0.0.1:100 (type 1)
     *   ESI 00:11:22:33:44:55:66:77:88:99, Eth Tag 0, Label 100
     *
     * EVPN NLRI entry:
     *   Route Type (1) + Length (1) + RD(8) + ESI(10) + EthTag(4) +
     *   MACLen(1) + MAC(6) + IPLen(1) + IP(4) + Label(3) = 40 bytes total
     *   (route-specific data = 38 bytes)
     *
     * MP_REACH_NLRI body:
     *   AFI(2) + SAFI(1) + NH_Len(1) + NH(4) + Reserved(1) + NLRI(40) = 49 bytes
     *
     * Path attr: flags(1) + type(1) + length(2) + body(49) = 53 bytes
     * Total: 19 (header) + 2 (withdrawn_len) + 2 (pa_len) + 53 (pa) = 76 bytes
     */

    unsigned char msg[76];
    int offset = make_bgp_header(msg, 76, UPDATE);

    /* Withdrawn routes length = 0 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    /* Path attributes length = 53 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x35;  /* 53 */

    /* MP_REACH_NLRI attribute (type 14, extended length) */
    msg[offset++] = 0x90;  /* Flags: Optional, Transitive, Extended Length */
    msg[offset++] = 0x0E;  /* Type: 14 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x31;  /* Length: 49 */

    /* AFI = 25 (L2VPN) */
    msg[offset++] = 0x00;
    msg[offset++] = 0x19;

    /* SAFI = 70 (EVPN) */
    msg[offset++] = 0x46;

    /* Next Hop Length = 4 */
    msg[offset++] = 0x04;

    /* Next Hop: 10.0.0.1 */
    msg[offset++] = 0x0A;
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;
    msg[offset++] = 0x01;

    /* Reserved */
    msg[offset++] = 0x00;

    /* EVPN NLRI: Type 2 (MAC/IP Advertisement) */
    msg[offset++] = 0x02;  /* Route Type = 2 */
    msg[offset++] = 38;    /* Length = 38 bytes of route data */

    /* RD: Type 1 (IP:number), IP=10.0.0.1, number=100 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x01;  /* RD Type 1 */
    msg[offset++] = 0x0A;  /* 10. */
    msg[offset++] = 0x00;  /* 0.  */
    msg[offset++] = 0x00;  /* 0.  */
    msg[offset++] = 0x01;  /* 1   */
    msg[offset++] = 0x00;
    msg[offset++] = 0x64;  /* 100 */

    /* ESI: 00:11:22:33:44:55:66:77:88:99 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x11;
    msg[offset++] = 0x22;
    msg[offset++] = 0x33;
    msg[offset++] = 0x44;
    msg[offset++] = 0x55;
    msg[offset++] = 0x66;
    msg[offset++] = 0x77;
    msg[offset++] = 0x88;
    msg[offset++] = 0x99;

    /* Ethernet Tag = 0 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    /* MAC Length = 48 bits */
    msg[offset++] = 0x30;

    /* MAC: aa:bb:cc:dd:ee:ff */
    msg[offset++] = 0xAA;
    msg[offset++] = 0xBB;
    msg[offset++] = 0xCC;
    msg[offset++] = 0xDD;
    msg[offset++] = 0xEE;
    msg[offset++] = 0xFF;

    /* IP Length = 32 bits */
    msg[offset++] = 0x20;

    /* IP: 192.168.1.1 */
    msg[offset++] = 0xC0;
    msg[offset++] = 0xA8;
    msg[offset++] = 0x01;
    msg[offset++] = 0x01;

    /* MPLS Label: 100 (encoded in 3 bytes: label<<4 | bottom-of-stack) */
    /* Label 100 = 0x64, encoded: 0x00 0x06 0x41 (100<<4 | 1) */
    msg[offset++] = 0x00;
    msg[offset++] = 0x06;
    msg[offset++] = 0x41;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for EVPN Type 2", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed) {
            test_cond("UPDATE type is correct", parsed->type == UPDATE);
            test_cond("MP_REACH_NLRI attribute exists",
                parsed->update->path_attrs[MP_REACH_NLRI] != NULL);

            if (parsed->update->path_attrs[MP_REACH_NLRI]) {
                struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;
                test_cond("mp_reach pointer is not NULL", mp != NULL);

                if (mp) {
                    test_cond("AFI is 25 (L2VPN)", mp->afi == BGP_AFI_L2VPN);
                    test_cond("SAFI is 70 (EVPN)", mp->safi == BGP_SAFI_EVPN);
                    test_cond("Next hop is 10.0.0.1",
                        strcmp(mp->nh_string, "10.0.0.1") == 0);
                    test_cond("NLRI list is not empty", !list_empty(&mp->nlri));

                    if (!list_empty(&mp->nlri)) {
                        struct evpn_nlri *nlri = list_entry(mp->nlri.next, struct evpn_nlri, list);
                        test_cond("Route type is 2", nlri->route_type == EVPN_MAC_IP_ADV);
                        test_cond("RD type is 1", nlri->rd_type == 1);
                        test_cond("RD value IP is 10.0.0.1",
                            nlri->rd_value[0] == 0x0A &&
                            nlri->rd_value[1] == 0x00 &&
                            nlri->rd_value[2] == 0x00 &&
                            nlri->rd_value[3] == 0x01);
                        test_cond("RD value number is 100",
                            nlri->rd_value[4] == 0x00 &&
                            nlri->rd_value[5] == 0x64);
                        test_cond("ESI byte 0 is 0x00", nlri->esi[0] == 0x00);
                        test_cond("ESI byte 1 is 0x11", nlri->esi[1] == 0x11);
                        test_cond("ESI byte 9 is 0x99", nlri->esi[9] == 0x99);
                        test_cond("Ethernet tag is 0", nlri->ethernet_tag == 0);
                        test_cond("MAC length is 48", nlri->mac_length == 48);
                        test_cond("MAC is aa:bb:cc:dd:ee:ff",
                            nlri->mac[0] == 0xAA &&
                            nlri->mac[1] == 0xBB &&
                            nlri->mac[2] == 0xCC &&
                            nlri->mac[3] == 0xDD &&
                            nlri->mac[4] == 0xEE &&
                            nlri->mac[5] == 0xFF);
                        test_cond("IP length is 32", nlri->ip_length == 32);
                        test_cond("IP is 192.168.1.1",
                            nlri->ip[0] == 0xC0 &&
                            nlri->ip[1] == 0xA8 &&
                            nlri->ip[2] == 0x01 &&
                            nlri->ip[3] == 0x01);
                        test_cond("MPLS label is 100", nlri->mpls_label1 == 100);
                    }
                }
            }

            free_msg(parsed);
        }
    }
}

void test_evpn_type3_inclusive_mcast(void) {
    test_section("EVPN Type 3 - Inclusive Multicast Ethernet Tag");

    /*
     * EVPN Type 3: RD(8) + EthTag(4) + IPLen(1) + IP(4) = 17 bytes
     * NLRI entry: Route Type(1) + Length(1) + 17 = 19 bytes
     *
     * MP_REACH_NLRI: AFI(2) + SAFI(1) + NHLen(1) + NH(4) + Reserved(1) + NLRI(19) = 28
     * Path attr: flags(1) + type(1) + length(2) + body(28) = 32
     * Total: 19 + 2 + 2 + 32 = 55 bytes
     */

    unsigned char msg[55];
    int offset = make_bgp_header(msg, 55, UPDATE);

    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* withdrawn = 0 */
    msg[offset++] = 0x00; msg[offset++] = 0x20;  /* pa_len = 32 */

    /* MP_REACH_NLRI */
    msg[offset++] = 0x90; msg[offset++] = 0x0E;  /* flags + type */
    msg[offset++] = 0x00; msg[offset++] = 0x1C;  /* length = 28 */

    msg[offset++] = 0x00; msg[offset++] = 0x19;  /* AFI 25 */
    msg[offset++] = 0x46;                         /* SAFI 70 */
    msg[offset++] = 0x04;                         /* NH len 4 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x02;  /* NH 10.0.0.2 */
    msg[offset++] = 0x00;                         /* Reserved */

    /* EVPN NLRI: Type 3 */
    msg[offset++] = 0x03;  /* Route type 3 */
    msg[offset++] = 17;    /* Length 17 */

    /* RD: Type 0, admin=65000, number=200 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* RD type 0 */
    msg[offset++] = 0xFD; msg[offset++] = 0xE8;  /* admin: 65000 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0xC8;  /* number: 200 */

    /* Ethernet Tag = 100 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x64;

    /* IP Length = 32 bits */
    msg[offset++] = 0x20;

    /* IP: 10.0.0.2 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x02;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for EVPN Type 3", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_REACH_NLRI]) {
            struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;

            if (mp && !list_empty(&mp->nlri)) {
                struct evpn_nlri *nlri = list_entry(mp->nlri.next, struct evpn_nlri, list);
                test_cond("Route type is 3", nlri->route_type == EVPN_INCLUSIVE_MCAST);
                test_cond("RD type is 0", nlri->rd_type == 0);
                test_cond("Ethernet tag is 100", nlri->ethernet_tag == 100);
                test_cond("IP length is 32", nlri->ip_length == 32);
                test_cond("IP is 10.0.0.2",
                    nlri->ip[0] == 0x0A && nlri->ip[1] == 0x00 &&
                    nlri->ip[2] == 0x00 && nlri->ip[3] == 0x02);
            }

            free_msg(parsed);
        } else if (parsed) {
            free_msg(parsed);
        }
    }
}

void test_evpn_type1_eth_auto_discovery(void) {
    test_section("EVPN Type 1 - Ethernet Auto-Discovery");

    /*
     * EVPN Type 1: RD(8) + ESI(10) + EthTag(4) + Label(3) = 25 bytes
     * NLRI entry: 1 + 1 + 25 = 27 bytes
     *
     * MP_REACH_NLRI: AFI(2) + SAFI(1) + NHLen(1) + NH(4) + Reserved(1) + NLRI(27) = 36
     * Path attr: 4 + 36 = 40
     * Total: 19 + 2 + 2 + 40 = 63 bytes
     */

    unsigned char msg[63];
    int offset = make_bgp_header(msg, 63, UPDATE);

    msg[offset++] = 0x00; msg[offset++] = 0x00;  /* withdrawn = 0 */
    msg[offset++] = 0x00; msg[offset++] = 0x28;  /* pa_len = 40 */

    msg[offset++] = 0x90; msg[offset++] = 0x0E;  /* flags + type */
    msg[offset++] = 0x00; msg[offset++] = 0x24;  /* length = 36 */

    msg[offset++] = 0x00; msg[offset++] = 0x19;  /* AFI 25 */
    msg[offset++] = 0x46;                         /* SAFI 70 */
    msg[offset++] = 0x04;                         /* NH len 4 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;  /* NH 10.0.0.1 */
    msg[offset++] = 0x00;                         /* Reserved */

    /* EVPN Type 1 */
    msg[offset++] = 0x01;  /* Route type 1 */
    msg[offset++] = 25;    /* Length */

    /* RD: Type 2 (4-byte ASN:number), ASN=4200000001, number=50 */
    msg[offset++] = 0x00; msg[offset++] = 0x02;  /* RD type 2 */
    msg[offset++] = 0xFA; msg[offset++] = 0x56;
    msg[offset++] = 0xEA; msg[offset++] = 0x01;  /* ASN: 4200000001 = 0xFA56EA01 */
    msg[offset++] = 0x00; msg[offset++] = 0x32;  /* number: 50 */

    /* ESI: all zeros */
    memset(msg + offset, 0, 10);
    offset += 10;

    /* Ethernet Tag = 4294967295 (max) */
    msg[offset++] = 0xFF; msg[offset++] = 0xFF;
    msg[offset++] = 0xFF; msg[offset++] = 0xFF;

    /* MPLS Label 500: bytes[0]=500>>12=0, bytes[1]=(500>>4)&0xFF=0x1F, bytes[2]=(500&0xF)<<4|1=0x41 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x1F;
    msg[offset++] = 0x41;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for EVPN Type 1", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_REACH_NLRI]) {
            struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;

            if (mp && !list_empty(&mp->nlri)) {
                struct evpn_nlri *nlri = list_entry(mp->nlri.next, struct evpn_nlri, list);
                test_cond("Route type is 1", nlri->route_type == EVPN_ETH_AUTO_DISCOVERY);
                test_cond("RD type is 2", nlri->rd_type == 2);
                test_cond("Ethernet tag is 4294967295", nlri->ethernet_tag == 0xFFFFFFFF);
                test_cond("ESI is all zeros",
                    nlri->esi[0] == 0 && nlri->esi[9] == 0);
                test_cond("MPLS label is 500", nlri->mpls_label1 == 500);
            }

            free_msg(parsed);
        } else if (parsed) {
            free_msg(parsed);
        }
    }
}

void test_evpn_type5_ip_prefix(void) {
    test_section("EVPN Type 5 - IP Prefix");

    /*
     * EVPN Type 5 (IPv4): RD(8) + ESI(10) + EthTag(4) + PrefixLen(1) + IP(4) + GW(4) + Label(3) = 34
     * NLRI entry: 1 + 1 + 34 = 36 bytes
     *
     * MP_REACH_NLRI: AFI(2) + SAFI(1) + NHLen(1) + NH(4) + Reserved(1) + NLRI(36) = 45
     * Path attr: 4 + 45 = 49
     * Total: 19 + 2 + 2 + 49 = 72 bytes
     */

    unsigned char msg[72];
    int offset = make_bgp_header(msg, 72, UPDATE);

    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x31;  /* pa_len = 49 */

    msg[offset++] = 0x90; msg[offset++] = 0x0E;
    msg[offset++] = 0x00; msg[offset++] = 0x2D;  /* length = 45 */

    msg[offset++] = 0x00; msg[offset++] = 0x19;  /* AFI 25 */
    msg[offset++] = 0x46;                         /* SAFI 70 */
    msg[offset++] = 0x04;                         /* NH len 4 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x00;                         /* Reserved */

    /* EVPN Type 5 */
    msg[offset++] = 0x05;
    msg[offset++] = 34;   /* Length */

    /* RD: Type 1, IP=172.16.0.1, number=1000 */
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0xAC; msg[offset++] = 0x10;
    msg[offset++] = 0x00; msg[offset++] = 0x01;  /* 172.16.0.1 */
    msg[offset++] = 0x03; msg[offset++] = 0xE8;  /* 1000 */

    /* ESI: all zeros */
    memset(msg + offset, 0, 10);
    offset += 10;

    /* Ethernet Tag = 0 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;

    /* IP Prefix Length = 24 */
    msg[offset++] = 0x18;

    /* IP Prefix: 192.168.10.0 */
    msg[offset++] = 0xC0; msg[offset++] = 0xA8;
    msg[offset++] = 0x0A; msg[offset++] = 0x00;

    /* Gateway IP: 0.0.0.0 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;

    /* MPLS Label 1000: bytes[0]=1000>>12=0, bytes[1]=(1000>>4)&0xFF=0x3E, bytes[2]=(1000&0xF)<<4|1=0x81 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x3E;
    msg[offset++] = 0x81;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for EVPN Type 5", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_REACH_NLRI]) {
            struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;

            if (mp && !list_empty(&mp->nlri)) {
                struct evpn_nlri *nlri = list_entry(mp->nlri.next, struct evpn_nlri, list);
                test_cond("Route type is 5", nlri->route_type == EVPN_IP_PREFIX);
                test_cond("RD type is 1", nlri->rd_type == 1);
                test_cond("Prefix length is 24", nlri->prefix_length == 24);
                test_cond("IP prefix is 192.168.10.0",
                    nlri->ip[0] == 0xC0 && nlri->ip[1] == 0xA8 &&
                    nlri->ip[2] == 0x0A && nlri->ip[3] == 0x00);
                test_cond("Gateway IP is 0.0.0.0",
                    nlri->gw_ip[0] == 0 && nlri->gw_ip[1] == 0 &&
                    nlri->gw_ip[2] == 0 && nlri->gw_ip[3] == 0);
                test_cond("IP length is 32", nlri->ip_length == 32);
                test_cond("MPLS label is 1000", nlri->mpls_label1 == 1000);
                test_cond("Ethernet tag is 0", nlri->ethernet_tag == 0);
            }

            free_msg(parsed);
        } else if (parsed) {
            free_msg(parsed);
        }
    }
}

void test_evpn_unreach(void) {
    test_section("EVPN MP_UNREACH_NLRI (withdrawn)");

    /*
     * EVPN Type 2 in MP_UNREACH_NLRI (no MPLS labels in unreach)
     * Type 2 without labels: RD(8) + ESI(10) + EthTag(4) + MACLen(1) + MAC(6) + IPLen(1) = 30
     * NLRI entry: 1 + 1 + 30 = 32 bytes
     *
     * MP_UNREACH_NLRI: AFI(2) + SAFI(1) + NLRI(32) = 35
     * Path attr: 4 + 35 = 39
     * Total: 19 + 2 + 2 + 39 = 62
     */

    unsigned char msg[62];
    int offset = make_bgp_header(msg, 62, UPDATE);

    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x27;  /* pa_len = 39 */

    /* MP_UNREACH_NLRI (type 15) */
    msg[offset++] = 0x90; msg[offset++] = 0x0F;
    msg[offset++] = 0x00; msg[offset++] = 0x23;  /* length = 35 */

    msg[offset++] = 0x00; msg[offset++] = 0x19;  /* AFI 25 */
    msg[offset++] = 0x46;                         /* SAFI 70 */

    /* EVPN Type 2 (no labels) */
    msg[offset++] = 0x02;
    msg[offset++] = 30;   /* Length */

    /* RD: Type 1, 10.0.0.1:100 */
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x00; msg[offset++] = 0x64;

    /* ESI: zeros */
    memset(msg + offset, 0, 10);
    offset += 10;

    /* Ethernet Tag = 0 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;

    /* MAC Length = 48 */
    msg[offset++] = 0x30;

    /* MAC: 11:22:33:44:55:66 */
    msg[offset++] = 0x11; msg[offset++] = 0x22;
    msg[offset++] = 0x33; msg[offset++] = 0x44;
    msg[offset++] = 0x55; msg[offset++] = 0x66;

    /* IP Length = 0 (no IP) */
    msg[offset++] = 0x00;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for EVPN unreach", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_UNREACH_NLRI]) {
            struct mp_unreach_nlri *mp = parsed->update->path_attrs[MP_UNREACH_NLRI]->mp_unreach;
            test_cond("mp_unreach pointer is not NULL", mp != NULL);

            if (mp) {
                test_cond("AFI is 25 (L2VPN)", mp->afi == BGP_AFI_L2VPN);
                test_cond("SAFI is 70 (EVPN)", mp->safi == BGP_SAFI_EVPN);
                test_cond("Withdrawn list is not empty", !list_empty(&mp->withdrawn));

                if (!list_empty(&mp->withdrawn)) {
                    struct evpn_nlri *nlri = list_entry(mp->withdrawn.next, struct evpn_nlri, list);
                    test_cond("Route type is 2", nlri->route_type == EVPN_MAC_IP_ADV);
                    test_cond("MAC is 11:22:33:44:55:66",
                        nlri->mac[0] == 0x11 && nlri->mac[1] == 0x22 &&
                        nlri->mac[2] == 0x33 && nlri->mac[3] == 0x44 &&
                        nlri->mac[4] == 0x55 && nlri->mac[5] == 0x66);
                    test_cond("IP length is 0 (no IP)", nlri->ip_length == 0);
                    test_cond("MPLS label1 is 0 (no label in unreach)",
                        nlri->mpls_label1 == 0);
                }
            }

            free_msg(parsed);
        } else if (parsed) {
            free_msg(parsed);
        }
    }
}

void test_evpn_multiple_nlri(void) {
    test_section("EVPN multiple NLRI entries");

    /*
     * Two EVPN Type 3 routes in one MP_REACH_NLRI
     * Each Type 3: 1 + 1 + 17 = 19 bytes, total NLRI = 38 bytes
     *
     * MP_REACH_NLRI: AFI(2) + SAFI(1) + NHLen(1) + NH(4) + Reserved(1) + NLRI(38) = 47
     * Path attr: 4 + 47 = 51
     * Total: 19 + 2 + 2 + 51 = 74
     */

    unsigned char msg[74];
    int offset = make_bgp_header(msg, 74, UPDATE);

    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x33;  /* pa_len = 51 */

    msg[offset++] = 0x90; msg[offset++] = 0x0E;
    msg[offset++] = 0x00; msg[offset++] = 0x2F;  /* length = 47 */

    msg[offset++] = 0x00; msg[offset++] = 0x19;  /* AFI 25 */
    msg[offset++] = 0x46;                         /* SAFI 70 */
    msg[offset++] = 0x04;                         /* NH len 4 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x00;                         /* Reserved */

    /* First Type 3 route */
    msg[offset++] = 0x03;
    msg[offset++] = 17;
    msg[offset++] = 0x00; msg[offset++] = 0x01;  /* RD type 1 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x0A;  /* Eth tag = 10 */
    msg[offset++] = 0x20;                         /* IP len = 32 */
    msg[offset++] = 0x0A; msg[offset++] = 0x01;
    msg[offset++] = 0x01; msg[offset++] = 0x01;  /* 10.1.1.1 */

    /* Second Type 3 route */
    msg[offset++] = 0x03;
    msg[offset++] = 17;
    msg[offset++] = 0x00; msg[offset++] = 0x01;  /* RD type 1 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x02;
    msg[offset++] = 0x00; msg[offset++] = 0x02;
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x14;  /* Eth tag = 20 */
    msg[offset++] = 0x20;                         /* IP len = 32 */
    msg[offset++] = 0x0A; msg[offset++] = 0x02;
    msg[offset++] = 0x02; msg[offset++] = 0x02;  /* 10.2.2.2 */

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for multiple EVPN NLRI", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_REACH_NLRI]) {
            struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;

            if (mp) {
                /* Count NLRI entries */
                int count = 0;
                struct list_head *pos;
                list_for_each(pos, &mp->nlri) { count++; }
                test_cond("Two NLRI entries parsed", count == 2);

                if (count == 2) {
                    struct evpn_nlri *first = list_entry(mp->nlri.next, struct evpn_nlri, list);
                    struct evpn_nlri *second = list_entry(first->list.next, struct evpn_nlri, list);

                    test_cond("First route ethernet_tag is 10", first->ethernet_tag == 10);
                    test_cond("First route IP is 10.1.1.1",
                        first->ip[0] == 0x0A && first->ip[3] == 0x01);
                    test_cond("Second route ethernet_tag is 20", second->ethernet_tag == 20);
                    test_cond("Second route IP is 10.2.2.2",
                        second->ip[0] == 0x0A && second->ip[3] == 0x02);
                }
            }

            free_msg(parsed);
        } else if (parsed) {
            free_msg(parsed);
        }
    }
}

void test_evpn_type2_mac_only(void) {
    test_section("EVPN Type 2 - MAC only (no IP)");

    /*
     * Type 2 with MAC only (ip_length=0): RD(8) + ESI(10) + EthTag(4) + MACLen(1) + MAC(6) + IPLen(1) + Label(3) = 33
     * NLRI entry: 1 + 1 + 33 = 35 bytes
     *
     * MP_REACH_NLRI: AFI(2) + SAFI(1) + NHLen(1) + NH(4) + Reserved(1) + NLRI(35) = 44
     * Path attr: 4 + 44 = 48
     * Total: 19 + 2 + 2 + 48 = 71
     */

    unsigned char msg[71];
    int offset = make_bgp_header(msg, 71, UPDATE);

    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x30;  /* pa_len = 48 */

    msg[offset++] = 0x90; msg[offset++] = 0x0E;
    msg[offset++] = 0x00; msg[offset++] = 0x2C;  /* length = 44 */

    msg[offset++] = 0x00; msg[offset++] = 0x19;  /* AFI 25 */
    msg[offset++] = 0x46;                         /* SAFI 70 */
    msg[offset++] = 0x04;                         /* NH len 4 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x00;                         /* Reserved */

    /* EVPN Type 2 */
    msg[offset++] = 0x02;
    msg[offset++] = 33;   /* Length (no IP, with label) */

    /* RD: Type 0, admin=65001, number=1 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0xFD; msg[offset++] = 0xE9;  /* 65001 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;  /* 1 */

    /* ESI: zeros */
    memset(msg + offset, 0, 10);
    offset += 10;

    /* Ethernet Tag = 0 */
    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x00;

    /* MAC Length = 48 */
    msg[offset++] = 0x30;

    /* MAC: de:ad:be:ef:ca:fe */
    msg[offset++] = 0xDE; msg[offset++] = 0xAD;
    msg[offset++] = 0xBE; msg[offset++] = 0xEF;
    msg[offset++] = 0xCA; msg[offset++] = 0xFE;

    /* IP Length = 0 (no IP) */
    msg[offset++] = 0x00;

    /* MPLS Label 200: bytes[0]=200>>12=0, bytes[1]=(200>>4)&0xFF=0x0C, bytes[2]=(200&0xF)<<4|1=0x81 */
    msg[offset++] = 0x00;
    msg[offset++] = 0x0C;
    msg[offset++] = 0x81;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for EVPN Type 2 MAC-only", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_REACH_NLRI]) {
            struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;

            if (mp && !list_empty(&mp->nlri)) {
                struct evpn_nlri *nlri = list_entry(mp->nlri.next, struct evpn_nlri, list);
                test_cond("Route type is 2", nlri->route_type == EVPN_MAC_IP_ADV);
                test_cond("MAC is de:ad:be:ef:ca:fe",
                    nlri->mac[0] == 0xDE && nlri->mac[1] == 0xAD &&
                    nlri->mac[2] == 0xBE && nlri->mac[3] == 0xEF &&
                    nlri->mac[4] == 0xCA && nlri->mac[5] == 0xFE);
                test_cond("IP length is 0", nlri->ip_length == 0);
                test_cond("MPLS label is 200", nlri->mpls_label1 == 200);
            }

            free_msg(parsed);
        } else if (parsed) {
            free_msg(parsed);
        }
    }
}

void test_evpn_truncated(void) {
    test_section("EVPN truncated NLRI (error handling)");

    /*
     * EVPN NLRI with route_length claiming more data than available.
     * Should fail gracefully (return NULL from parse_evpn_nlri).
     *
     * MP_REACH_NLRI: AFI(2) + SAFI(1) + NHLen(1) + NH(4) + Reserved(1) + NLRI(4) = 13
     * NLRI: type(1) + length(1) + only 2 bytes of data (claims 38)
     *
     * Path attr: 4 + 13 = 17
     * Total: 19 + 2 + 2 + 17 = 40
     */

    unsigned char msg[40];
    int offset = make_bgp_header(msg, 40, UPDATE);

    msg[offset++] = 0x00; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x11;  /* pa_len = 17 */

    msg[offset++] = 0x90; msg[offset++] = 0x0E;
    msg[offset++] = 0x00; msg[offset++] = 0x0D;  /* length = 13 */

    msg[offset++] = 0x00; msg[offset++] = 0x19;  /* AFI 25 */
    msg[offset++] = 0x46;                         /* SAFI 70 */
    msg[offset++] = 0x04;                         /* NH len 4 */
    msg[offset++] = 0x0A; msg[offset++] = 0x00;
    msg[offset++] = 0x00; msg[offset++] = 0x01;
    msg[offset++] = 0x00;                         /* Reserved */

    /* Truncated EVPN NLRI: claims length 38 but only 2 bytes follow */
    msg[offset++] = 0x02;  /* Route type 2 */
    msg[offset++] = 38;    /* Length claims 38 bytes */
    msg[offset++] = 0x00;  /* Only 2 bytes of data */
    msg[offset++] = 0x01;

    int fd = create_test_socket(msg, sizeof(msg));
    test_cond("Created test socket for truncated EVPN", fd >= 0);

    if (fd >= 0) {
        struct bgp_peer *peer = create_test_peer(fd, 0);
        struct bgp_msg *parsed = recv_msg(peer);
        close(fd);
        free_test_peer(peer);

        test_cond("recv_msg returns non-NULL (UPDATE parsed)", parsed != NULL);

        if (parsed && parsed->update->path_attrs[MP_REACH_NLRI]) {
            struct mp_reach_nlri *mp = parsed->update->path_attrs[MP_REACH_NLRI]->mp_reach;

            if (mp) {
                test_cond("NLRI list is empty (truncated entry rejected)",
                    list_empty(&mp->nlri));
            }

            free_msg(parsed);
        } else if (parsed) {
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

    // Capability tests
    test_capabilities_create_free();
    test_capabilities_add_route_refresh();
    test_capabilities_add_mp_ext();
    test_capabilities_add_four_octet_asn();
    test_capabilities_encode();
    test_capabilities_encode_multiple();
    test_send_open_no_caps();
    test_send_open_with_caps();
    test_send_open_round_trip();

    // MP_REACH_NLRI and MP_UNREACH_NLRI tests (IPv6)
    test_update_mp_reach_ipv6();
    test_update_mp_unreach_ipv6();
    test_update_mp_reach_dual_nexthop();

    // EVPN (RFC 7432) parsing tests
    test_evpn_type2_mac_ip();
    test_evpn_type3_inclusive_mcast();
    test_evpn_type1_eth_auto_discovery();
    test_evpn_type5_ip_prefix();
    test_evpn_unreach();
    test_evpn_multiple_nlri();
    test_evpn_type2_mac_only();
    test_evpn_truncated();

    test_report();
}
