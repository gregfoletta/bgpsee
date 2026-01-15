# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Install dependency (required)
sudo apt install libjansson-dev    # Debian/Ubuntu
sudo yum install jansson-devel     # Red Hat/CentOS

# Build
make

# Clean
make clean
```

The build produces a `bgpsee` executable in the root directory. There is no `make install`.

**Note**: Debug builds are the default. The Makefile enables address/undefined behavior sanitizers and debug symbols. For release builds, modify `DEBUG_FLAGS` in the Makefile.

## Architecture

BGPSee is a multi-threaded BGP client that peers with routers and outputs received BGP messages (OPEN, UPDATE, KEEPALIVE, NOTIFICATION) in JSON or key-value format.

### Threading Model

- **Main thread**: CLI argument parsing, peer initialization, lifecycle management
- **Per-peer threads**: Each BGP peer runs in its own thread (`bgp_peer.thread`)
- **Mutex**: `stdout_lock` per peer prevents output corruption

### Core Components

| File | Purpose |
|------|---------|
| `main.c` | Entry point, CLI parsing with getopt_long |
| `bgp.c` | BGP instance/peer lifecycle, FSM implementation |
| `bgp_message.c` | BGP protocol message parsing (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) |
| `bgp_print.c` | Output formatting (JSON via jansson, key-value) |
| `bgp_timers.c` | RFC-compliant timer management using Linux timerfd |
| `tcp_client.c` | TCP socket connection handling |

### Key Data Structures

- `struct bgp_instance` (`bgp.h`): Holds local ASN/RID, manages up to 256 peers
- `struct bgp_peer` (`bgp_peer.h`): Per-peer state including FSM state, socket, timers, thread
- BGP message structures (`bgp_message.h`): OPEN, UPDATE, NOTIFICATION with path attributes

### BGP FSM States

IDLE → CONNECT → ACTIVE → OPENSENT → OPENCONFIRM → ESTABLISHED

FSM functions in `bgp.c`: `fsm_state_idle()`, `fsm_state_connect()`, etc.

### External Dependencies

- **jansson**: JSON output formatting
- **sds**: Simple Dynamic Strings (git submodule in `src/sds/`)
- **list.h**: Linux kernel-style doubly-linked list

## Running

```bash
./bgpsee -a <local-asn> -r <router-id> <peer-ip>,<peer-asn>[,<name>]

# Example
./bgpsee -f json --asn 65001 10.0.0.1,65011,"Upstream Router"
```

Output formats: `json` (default) or `kv` (key-value)
