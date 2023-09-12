# BGPSee

![Build Tests](https://github.com/gregfoletta/bgpsee/actions/workflows/make.yml/badge.svg)

<p align="center">
  <img src="https://github.com/gregfoletta/bgpsee/blob/master/img/logo.png"/>
</p>

BGPSee is a multi-threaded BGP client for the CLI. It's goal it to allow you to quickly and easily view the BGP paths that a peer or peers are advertising. Previously you would have had to either spin-up a virtual routers, or use a Linux routing daemon (FRR, Zebra, etc) to view this information.

# Version

Current version is **0.0.2** ([CHAGELOG](CHANGELOG.md)

Versions < 0.1.0 are considered beta version of bgpsee. There may be rough edges, and the CLI interface is subject to major changes between versions. By default BGPSee will compile with debug symbols and a number of other compile-time sanitisation flags. If bgpsee crashes, I would ask you to please raise an issue and copy/paste the crash output into the issue.

# Usage

```
./bgpsee [options...] <peer> [<peer> ...]"
    -s, --source <ip>           IP BGP connection is sourced from
    -a, --asn <asn>             Local ASN of bgpsee. If not provided 65000 will be used
    -r, --rid <ip>              Local router ID of bgpsee. If not provided 1.1.1.1 will be used
    -l, --logging <lvl>         Logging output level, 0: BGP messages only, 1: Errors, 2: Warnings, 3: Info (default), 4: Debug
    -h, --help                  Print a help message

<peer> formats: <ip>,<asn> or <ip>,<asn>,<name>
```

# Example

Here's an example of *bgpsee* peering with an external router:

```
# ./bgpsee fw1.i.foletta.xyz,65001,Internal_Rtr_1
- Press Ctrl+D to exit
- Opening connection to fw1.i.foletta.xyz,65001 (Internal_Rtr_1)
- Connection to Internal_Rtr_1 successful
recv_time=1694549778 name=Internal_Rtr_1 id=0 type=OPEN length=69 version=4, asn=65001, hold_time=180, router_id=16790026, param_len=40
recv_time=1694549778 name=Internal_Rtr_1 id=1 type=KEEPALIVE length=19
recv_time=1694549786 name=Internal_Rtr_1 id=2 type=KEEPALIVE length=19
recv_time=1694549795 name=Internal_Rtr_1 id=3 type=KEEPALIVE length=19
recv_time=1694549804 name=Internal_Rtr_1 id=4 type=KEEPALIVE length=19
recv_time=1694549808 name=Internal_Rtr_1 id=5 type=UPDATE length=59 widthdrawn_route_length=0 withdrawn_routes="" path_attribute_length=18 origin=IGP n_as_segments=1 n_total_as=1 as_path="65001" next_hop=10.50.254.1 nlri="10.50.8.0/24,10.50.255.0/24,10.50.254.2/32,10.50.254.1/32"
recv_time=1694549808 name=Internal_Rtr_1 id=6 type=UPDATE length=80 widthdrawn_route_length=0 withdrawn_routes="" path_attribute_length=20 origin=IGP n_as_segments=1 n_total_as=2 as_path="65001,65011" next_hop=10.50.254.1 nlri="10.50.9.0/24,10.51.255.6/31,10.51.255.4/31,10.51.255.2/31,10.51.255.0/31,10.51.253.0/24,10.51.252.0/24,10.50.254.254/32"
recv_time=1694549812 name=Internal_Rtr_1 id=7 type=KEEPALIVE length=19
- Shutting down peers..
- Peer Internal_Rtr_1 has closed
```

We see a connection to an external router, with the peer router sending an OPEN and an immediate KEEPALIVE signalling it accepts the OPEN message we sent. After 30 seconds (the default [advertisement interval](https://datatracker.ietf.org/doc/html/rfc4271#section-9.2.1.1)) and a few KEEPALIVES, the peer sends us two UPDATE messages, each representing a different path. 

# Building

To build simply download/clone and build using make:
```
git clone https://github.com/gregfoletta/bgpsee.git
cd bgpsee
make
```

This builds a `bgpsee` executable in the root directory. There is no make install.

# Roadmap

Top 3 items to add in future releases:

- Improved error handling
- Expansion on the BGP Path Attribute handling, with a priority on:
    - [COMMUNITY](https://www.iana.org/go/rfc1997)
    - [EXTENDED COMMUNITIES](https://www.iana.org/go/rfc4360)
    - [MP_REACH_NLRI](https://www.iana.org/go/rfc4760)
- JSON output option for BGP messages
