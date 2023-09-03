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
./bgpsee [options...] <peer> [<peer> ...]\n"
    -s, --source <ip>           IP BGP connection is sourced from
    -a, --asn <asn>             Local ASN of bgpsee. If not provided 65000 will be used
    -r, --rid <ip>              Local router ID of bgpsee. If not provided 1.1.1.1 will be used
    -l, --logging <lvl>         Logging output level, 0: BGP messages only, 1: Errors, 2: Warnings, 3: Info (default), 4: Debug
    -h, --help\                 Print a help message

<peer> formats: <ip>,<asn> or <ip>,<asn>,<name>
```

# Example

The first example is a simple peering with an upstream router. We see

- The OPEN message
- A KEEPALIVE confirming that there are no errors in the OPEN message we sent.
- An UPDATE (and therefore a single path) with four pieces of network layer reachability information (NLRI).
- An UPDATE withdrawing the 10.50.11.0/24 route
- A KEEPALIVE 
- An UPDATE reannouncing the 10.50.11.0/24 route

```
./bgpsee --peer-ip 10.50.0.8 --name Local_Peer --local-asn 65001 --peer-asn 65011
recv_time=1688085528 name=Local_Peer id=0 type=OPEN, length=89 version=4, asn=65011, hold_time=180, router_id=33686018, param_len=60
recv_time=1688085528 name=Local_Peer id=1 type=KEEPALIVE, length=19
recv_time=1688085530 name=Local_Peer id=2 type=UPDATE, length=65 widthdrawn_route_length=0 withdrawn_routes="" path_attribute_length=26 origin=IGP n_as_segments=1, n_total_as=1 as_path="65011" nlri="10.50.9.0/24,10.52.0.0/16,10.50.254.254/32,10.50.11.0/24"
recv_time=1688085532 name=Local_Peer id=3 type=UPDATE, length=27 widthdrawn_route_length=4 withdrawn_routes="10.50.11.0/24" path_attribute_length=0 nlri=""
recv_time=1688085538 name=Local_Peer id=4 type=KEEPALIVE, length=19
recv_time=1688085541 name=Local_Peer id=5 type=UPDATE, length=53 widthdrawn_route_length=0 withdrawn_routes="" path_attribute_length=26 origin=IGP n_as_segments=1, n_total_as=1 as_path="65011" nlri="10.50.11.0/24"

```

With access to a full internet table (thank you [Andrew Vinton](https://www.linkedin.com/in/andrew-vinton/)), we can use bgpsee with other command line utilities to find out interesting statistics. First off: what's the total number of paths at a point in time:

```
./bgpsee --peer-ip <removed> --local-asn 65001 --peer-asn <removed> |\
grep UPDATE |\
wc -l

139006
```


Or what is the longest ASN path on the internet:

```
./bgpsee --peer-ip <removed> --local-asn 65001 --peer-asn 45270 |\
grep UPDATE |\
cut -d' ' -f12,13 |\
egrep -o "[[:digit:]]+ .*" |\
sort -nr |\
head -n1

131 as_path="4764,9002,30844,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447,37447"
```

Looks like [Orange in the Democratic Republic of the Congo](https://www.peeringdb.com/asn/37447) has a prepend typo, or *really* wants this to be a less preferable path.
  
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
