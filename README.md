# BGPSee

[![Build](https://github.com/gregfoletta/bgpsee/actions/workflows/make.yml/badge.svg)](https://github.com/gregfoletta/bgpsee/actions/workflows/make.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Language: C](https://img.shields.io/badge/Language-C-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.linux.org/)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)

<p align="center">
  <img src="https://github.com/gregfoletta/bgpsee/blob/master/img/logo.png"/>
</p>

BGPSee is a multi-threaded BGP client for the CLI. Its goal is to allow you to quickly and easily view the BGP paths that a peer or peers are advertising. Previously you would have had to either spin up virtual routers, or use a Linux routing daemon (FRR, Zebra, etc) to view this information.

## Features

- **Multi-peer support** - Connect to multiple BGP peers simultaneously, each in its own thread
- **JSON output** - Structured JSON output for easy parsing and integration with other tools
- **RFC compliant** - Proper BGP FSM implementation with NOTIFICATION support for error handling
- **Graceful shutdown** - Sends proper CEASE notifications when disconnecting
- **Lightweight** - No heavy dependencies, just libjansson for JSON support

## What It Doesn't Do

BGPSee is a passive observation tool, not a routing daemon. Compared to an RFC-compliant implementation (FRR, BIRD, OpenBGPd):

- **No route installation** - Does not install received routes into the kernel RIB/FIB
- **No route advertisement** - Does not originate or advertise any routes to peers
- **No best path selection** - Does not run the BGP decision process over received paths
- **No route policy** - No import/export filters, route-maps, or prefix-lists
- **No route reflection or confederations** - No RR client/non-client or sub-AS handling
- **No graceful restart** - Does not preserve forwarding state across restarts
- **No BFD integration** - No fast failure detection via BFD
- **No route redistribution** - Does not exchange routes with other protocols (OSPF, IS-IS, static)

In short, BGPSee establishes a session, receives UPDATEs, and outputs them as JSON. It never influences forwarding.

## Protocol Support

**Capabilities negotiated in OPEN:**
- Route Refresh (RFC 2918)
- Multiprotocol Extensions (RFC 4760): IPv4/IPv6 Unicast, L2VPN/EVPN, VPNv4
- 4-Octet AS Number (RFC 6793)

**Path attributes parsed:**
- ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR
- COMMUNITY (RFC 1997), LARGE_COMMUNITY (RFC 8092)
- MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 4760)

**Address families:**
- IPv4/IPv6 Unicast
- EVPN (RFC 7432): Route types 1-5
- VPNv4/MPLS-VPN (RFC 4364)

# Version

Current version is **0.0.9**

Major changes from **0.0.8** to **0.0.9**:
- VPNv4/MPLS-VPN address family parsing (RFC 4364)
- ADD-PATH capability infrastructure (RFC 7911)
- Configurable BGP hold time (`--hold-time` option, default 600s)

Major changes from **0.0.7** to **0.0.8**:
- 4-byte ASN support (RFC 6793)
- COMMUNITY path attribute parsing (RFC 1997)
- LARGE_COMMUNITY path attribute parsing (RFC 8092)
- Timestamp added to log messages

See the [CHANGELOG](CHANGELOG.md) for further information.

Versions < 0.1.0 are considered beta version of bgpsee. There may be rough edges, and the CLI interface is subject to major changes between versions. Use `make debug` to compile with debug symbols and sanitizers for development. If bgpsee crashes, I would ask you to please raise an issue and copy/paste the crash output into the issue.

# Usage

```
Usage: bgpsee [options...] <peer> [<peer> ...]
-s, --source <ip>	IP to source BGP connection from
-a, --asn <asn>		Local ASN of bgpsee. If not provided 65000 will be used.
-r, --rid <ip>		Local router ID of bgpsee. If not provided 1.1.1.1 will be used.
-l, --logging <level>	Logging output level, 0: BGP messages only, 1: Errors, 2: Warnings, 3: Info (default), 4: Debug
-f, --format <fmt>	Format of the output, <fmt> may be 'json' (pretty) or 'jsonl' (single line). Defaults to 'json'
-h, --help		Print this help message

<peer> formats: <ip>,<asn> or <ip>,<asn>,<name>
```

# Example

Here's an example of an UPDATE recieved from the global routing table. You can see the AS path, next hop, aggregator, and community path attributes, and the NLRI associated with these.

```sh
./bgpsee -f json --asn 65001 external.test,65011,"external"
```
```json
{
  "time": 1769291475,
  "peer_name": "external"
  "id": 3722,
  "type": "UPDATE",
  "length": 105,
  "message": {
    "withdrawn_route_length": 0,
    "withdrawn_routes": [],
    "path_attribute_length": 66,
    "path_attributes": {
      "ORIGIN": "IGP",
      "AS_PATH": {
        "n_as_segments": 1,
        "n_total_as": 5,
        "path_segments": [
          {
            "type": "AS_SEQUENCE",
            "n_as": 5,
            "asns": [
              65011,
              15694,
              174,
              3491,
              10361
            ]
          }
        ]
      },
      "NEXT_HOP": ""192.0.2.1,
      "AGGREGATOR": {
        "aggregator_asn": 10361,
        "aggregator_ip": "1.47.249.10"
      },
      "COMMUNITY": [
        "174:21100",
        "174:22010",
        "15694:174",
        "15694:1011"
      ]
    },
    "nlri": [
      "69.191.207.0/24",
      "69.191.183.0/24",
      "69.191.182.0/24",
      "69.191.84.0/24"
    ]
  }
}
```

# Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a detailed description of the threading model, key data structures, BGP FSM implementation, and message flow.

# Building

As of version 0.0.3, *bgpsee* now requires libjansson. You'll need to install the development libraries before building, for example

```
# Debian based distros
sudo apt install libjansson-dev

# Red Hat based distros
sudo yum install jansson-devel

# macOS (Homebrew)
brew install jansson
```

To build simply download/clone and build using make:
```
git clone --recurse-submodules https://github.com/gregfoletta/bgpsee.git
cd bgpsee
make
```

This builds a *bgpsee* executable in the root directory. There is no make install.

## Testing

Run the test suite with:
```bash
make test
```

This runs 318 tests covering:
- Byte conversion functions (big-endian network byte order)
- BGP message parsing (OPEN, UPDATE, KEEPALIVE, NOTIFICATION)
- MP_REACH/MP_UNREACH (IPv6, EVPN, VPNv4)
- EVPN route types 1-5 (MAC/IP, Inclusive Multicast, IP Prefix, etc.)
- VPNv4/MPLS-VPN (RFC 4364)
- Capability negotiation encoding/decoding
- NOTIFICATION message generation
- Invalid input handling (truncated data, bad lengths)

For development, use the debug build which includes AddressSanitizer and UndefinedBehaviorSanitizer:
```bash
make debug
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `make test` to ensure all tests pass
5. Submit a pull request

Please report bugs and crashes by [opening an issue](https://github.com/gregfoletta/bgpsee/issues).

# Roadmap

Top items to add in future releases:
- VPNv6 Address Family (AFI: 2, SAFI: 128)
- ADD-PATH (RFC 7911)

# AI Acknowledgement

Versions 0.0.1 and 0.0.2 were written entirely without AI assistance. The core architecture, multi-threading, output queuing, BGP FSM, CLI parsing, and timer management, was designed and implemented by hand.

From version 0.0.3 onwards, Claude (Anthropic) has been used to accelerate development, primarily for:
- Writing unit tests for message parsing
- Implementing multiprotocol extensions (EVPN, VPNv4)
- Adding path attribute parsers

This project was not generated from scratch by AI. The foundational design decisions and core networking code predate any AI involvement.
