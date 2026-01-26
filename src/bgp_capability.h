#pragma once

#include <stdint.h>
#include <stddef.h>
#include "list.h"

/*
 * BGP Capabilities (RFC 5492)
 *
 * Capabilities are advertised in OPEN messages as optional parameters.
 * Optional Parameter Type 2 = Capabilities
 *
 * Format:
 *   +--------------------------------------------------+
 *   | Capability Code (1 octet)                        |
 *   +--------------------------------------------------+
 *   | Capability Length (1 octet)                      |
 *   +--------------------------------------------------+
 *   | Capability Value (variable)                      |
 *   +--------------------------------------------------+
 */

/*
 * BGP Capability Codes (IANA assigned)
 * https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
 */
enum bgp_capability_code {
    BGP_CAP_MP_EXT              = 1,   /* Multiprotocol Extensions (RFC 2858) */
    BGP_CAP_ROUTE_REFRESH       = 2,   /* Route Refresh (RFC 2918) */
    BGP_CAP_ORF                 = 3,   /* Outbound Route Filtering (RFC 5291) */
    BGP_CAP_EXTENDED_NEXTHOP    = 5,   /* Extended Next Hop Encoding (RFC 8950) */
    BGP_CAP_EXTENDED_MESSAGE    = 6,   /* BGP Extended Message (RFC 8654) */
    BGP_CAP_GRACEFUL_RESTART    = 64,  /* Graceful Restart (RFC 4724) */
    BGP_CAP_FOUR_OCTET_ASN      = 65,  /* 4-octet AS Number (RFC 6793) */
    BGP_CAP_ADD_PATH            = 69,  /* ADD-PATH (RFC 7911) */
    BGP_CAP_ENHANCED_REFRESH    = 70,  /* Enhanced Route Refresh (RFC 7313) */
    BGP_CAP_FQDN                = 73,  /* FQDN Capability */
};

/*
 * Address Family Identifiers (AFI) for Multiprotocol Extensions
 * https://www.iana.org/assignments/address-family-numbers/
 */
enum bgp_afi {
    BGP_AFI_IPV4    = 1,
    BGP_AFI_IPV6    = 2,
    BGP_AFI_L2VPN   = 25,
};

/*
 * Subsequent Address Family Identifiers (SAFI)
 * https://www.iana.org/assignments/safi-namespace/
 */
enum bgp_safi {
    BGP_SAFI_UNICAST    = 1,
    BGP_SAFI_MULTICAST  = 2,
    BGP_SAFI_MPLS       = 4,
    BGP_SAFI_EVPN       = 70,
    BGP_SAFI_MPLS_VPN   = 128,  /* MPLS-labeled VPN (RFC 4364) */
};

/*
 * Generic capability structure
 * Supports any capability via the flexible value field
 */
struct bgp_capability {
    uint8_t code;           /* Capability code */
    uint8_t length;         /* Length of value (0-255) */
    uint8_t *value;         /* Capability-specific data (NULL if length=0) */
    struct list_head list;  /* For linking capabilities together */
};

/*
 * Capability list container
 * Used to build a set of capabilities to send in OPEN
 */
struct bgp_capabilities {
    int count;                  /* Number of capabilities */
    size_t total_length;        /* Total encoded length (for optional params) */
    struct list_head caps;      /* List of struct bgp_capability */
};

/*
 * Capability list management
 */
struct bgp_capabilities *bgp_capabilities_create(void);
void bgp_capabilities_free(struct bgp_capabilities *caps);

/*
 * Add a generic capability with arbitrary value
 * Returns 0 on success, -1 on error
 */
int bgp_capabilities_add(struct bgp_capabilities *caps,
                         uint8_t code, uint8_t length, const uint8_t *value);

/*
 * Convenience functions for common capabilities
 */

/* Route Refresh (RFC 2918) - no value */
int bgp_capabilities_add_route_refresh(struct bgp_capabilities *caps);

/* 4-octet AS Number (RFC 6793) - value is the 4-byte AS */
int bgp_capabilities_add_four_octet_asn(struct bgp_capabilities *caps, uint32_t asn);

/* Multiprotocol Extensions (RFC 2858) - value is AFI(2) + Reserved(1) + SAFI(1) */
int bgp_capabilities_add_mp_ext(struct bgp_capabilities *caps,
                                uint16_t afi, uint8_t safi);

/*
 * Encode capabilities into a buffer for OPEN message optional parameters
 * Returns number of bytes written, or -1 on error
 * Buffer must be large enough (use caps->total_length + 2 for param header)
 */
int bgp_capabilities_encode(const struct bgp_capabilities *caps,
                            unsigned char *buf, size_t buf_size);

/*
 * Parse capabilities from OPEN message optional parameters
 * Returns a new bgp_capabilities structure, or NULL on error
 * The opt_params buffer should point to the start of optional parameters
 * opt_param_len is the total length of all optional parameters
 */
struct bgp_capabilities *bgp_capabilities_parse(const unsigned char *opt_params,
                                                 uint8_t opt_param_len);

/*
 * Get capability name string from code
 * Returns a static string describing the capability
 */
const char *bgp_capability_name(uint8_t code);

/*
 * Check if 4-octet ASN capability is present and extract the ASN
 * Returns 1 if present (and sets *asn to the 4-byte ASN), 0 if not present
 */
int bgp_capabilities_has_four_octet_asn(const struct bgp_capabilities *caps, uint32_t *asn);

/*
 * ADD-PATH (RFC 7911) Support
 *
 * ADD-PATH capability allows multiple paths to be advertised for the same prefix.
 * When negotiated, each NLRI is prefixed with a 4-byte Path Identifier.
 */

/* ADD-PATH Send/Receive flags */
enum bgp_addpath_sr {
    BGP_ADDPATH_RECEIVE = 1,  /* Peer can receive ADD-PATH */
    BGP_ADDPATH_SEND    = 2,  /* Peer can send ADD-PATH */
    BGP_ADDPATH_BOTH    = 3,  /* Peer can send and receive ADD-PATH */
};

/*
 * ADD-PATH configuration per AFI/SAFI
 * Stores what we can receive from the peer (peer's send capability)
 */
struct bgp_addpath_config {
    uint8_t ipv4_unicast;    /* BGP_ADDPATH_* flags for AFI 1, SAFI 1 */
    uint8_t ipv6_unicast;    /* BGP_ADDPATH_* flags for AFI 2, SAFI 1 */
    uint8_t vpnv4;           /* BGP_ADDPATH_* flags for AFI 1, SAFI 128 */
    uint8_t evpn;            /* BGP_ADDPATH_* flags for AFI 25, SAFI 70 */
};

/*
 * Extract ADD-PATH configuration from capabilities
 * Populates config with the send/receive flags for each AFI/SAFI
 * Returns 1 if ADD-PATH capability found, 0 otherwise
 */
int bgp_capabilities_get_addpath(const struct bgp_capabilities *caps,
                                  struct bgp_addpath_config *config);

/*
 * Add ADD-PATH capability for an AFI/SAFI
 * sr_flags is a combination of BGP_ADDPATH_RECEIVE and BGP_ADDPATH_SEND
 */
int bgp_capabilities_add_addpath(struct bgp_capabilities *caps,
                                  uint16_t afi, uint8_t safi, uint8_t sr_flags);
