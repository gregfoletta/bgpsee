# BGPSee

![Build Tests](https://github.com/gregfoletta/bgpsee/actions/workflows/make.yml/badge.svg)

<p align="center">
  <img src="https://github.com/gregfoletta/bgpsee/blob/master/img/logo.png"/>
</p>

BGPSee is a multi-threaded BGP client for the CLI. It's goal it to allow you to quickly and easily view the BGP paths that a peer or peers are advertising. Previously you would have had to either spin-up a virtual routers, or use a Linux routing daemon (FRR, Zebra, etc) to view this information.

# Version

Current version is **0.0.4**

Major changes from **0.0.3** to **0.0.4**:
- Security fixes for BGP message parsing (bounds checking, input validation)
- Fixed byte conversion functions and memory leaks
- Added test suite (`make test`)
- Separate debug and release builds (`make` vs `make debug`) 

Seee the [CHANGELOG](CHANGELOG.md) for further information.

Versions < 0.1.0 are considered beta version of bgpsee. There may be rough edges, and the CLI interface is subject to major changes between versions. Use `make debug` to compile with debug symbols and sanitizers for development. If bgpsee crashes, I would ask you to please raise an issue and copy/paste the crash output into the issue.

# Usage

```
Usage: bgpsee [options...] <peer> [<peer> ...]
-s, --source <ip>	IP to source BGP connection from
-a, --asn <asn>		Local ASN of bgpsee. If not provided 65000 will be used.
-r, --rid <ip>		Local router ID of bgpsee. If not provided 1.1.1.1 will be used.
-l, --logging <level>	Logging output level, 0: BGP messages only, 1: Errors, 2: Warnings, 3: Info (default), 4: Debug 
-f, --format <fmt>	Format of the output, <fmt> may be 'json' or 'kv'. Defaults to 'json'
-h, --help		Print this help message

<peer> formats: <ip>,<asn> or <ip>,<asn>,<name>
```

# Example

Here's an example of *bgpsee* peering with an external router. You only see BGP messages recieved from the peer, not the messages sent by *bgpsee* iteslef.

```sh
./bgpsee -f json --asn 65001 fw1.i.foletta.xyz,65011,"External Router"
```
```json
{
  "recv_time": 1701025221,
  "peer_name": "External Router",
  "id": 0,
  "type": "OPEN",
  "length": 69,
  "message": {
    "version": 4,
    "asn": 65011,
    "hold_time": 180,
    "router_id": "10.50.254.1",
    "optional_parameter_length": 40
  }
}
{
  "recv_time": 1701025222,
  "peer_name": "External Router",
  "id": 1,
  "type": "KEEPALIVE",
  "length": 19,
  "message": {}
}
{
  "recv_time": 1701025844,
  "peer_name": "External Router",
  "id": 2336,
  "type": "UPDATE",
  "length": 97,
  "message": {
    "withdrawn_route_length": 0,
    "withdrawn_routes": [],
    "path_attribute_length": 70,
    "path_attributes": {
      "ORIGIN": "IGP",
      "AS_PATH": {
        "n_as_segments": 2,
        "n_total_as": 1,
        "path_segments": [
          {
            "type": "AS_SEQUENCE",
            "n_as": 5,
            "asns": [
              45270,
              4764,
              3356,
              1299,
              56595
            ]
          },
          {
            "type": "AS_SET",
            "n_as": 1,
            "asns": [
              23456
            ]
          }
        ]
      },
      "NEXT_HOP": "10.50.254.1",
      "AGGREGATOR": {
        "aggregator_asn": 56595,
        "aggregator_ip": "192.124.193.146"
      }
    },
    "nlri": [
      "5.172.183.0/24"
    ]
  }
}
```

We see a connection to an external router, with the peer router sending an OPEN and an immediate KEEPALIVE signalling it accepts the OPEN message we sent. After 5 seconds the peer starts sending UPDATEs from all of the paths it has. This router has a full BGP table, and shown is one of the paths that contains most of the path attributes, including AGGREGATOR and an AS_PATH with AS segments.

# Building

As of version 0.0.3, *bgpsee* now requires libjansson. You'll need to install the development libraries before building, for example

```
# Debian based distros
sudo apt install libjansson-dev

# Red Hat based distros
sudo yum install jansson-devel
```

To build simply download/clone and build using make:
```
git clone --recurse-submodules https://github.com/gregfoletta/bgpsee.git
cd bgpsee
make
```

This builds a *bgpsee* executable in the root directory. There is no make install.

# Roadmap

Top 3 items to add in future releases:

- Expansion on the BGP Path Attribute handling, with a priority on:
    - [COMMUNITY](https://www.iana.org/go/rfc1997)
    - [EXTENDED COMMUNITIES](https://www.iana.org/go/rfc4360)
    - [MP_REACH_NLRI](https://www.iana.org/go/rfc4760)
