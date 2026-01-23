# Change Log
- 0.0.8
    - Added 4-byte ASN support (RFC 6793)
    - Added COMMUNITY path attribute parsing (RFC 1997)
    - Added LARGE_COMMUNITY path attribute parsing (RFC 8092)
    - Added timestamp to log messages
    - Fixed header include guard issue causing build failures in CI

- 0.0.7
    - Added automatic reconnection with exponential backoff (`-R` flag)
    - Added output queue with dedicated writer thread to prevent keepalive stalls on slow stdout
    - Fixed FSM race condition where KEEPALIVE arriving with timer expiry caused false hold timer failures
    - Added hold time negotiation per RFC 4271 (uses min of local and peer hold times)
    - HoldTimer now correctly reset on UPDATE messages per RFC 4271

- 0.0.6
    - Added IPv6 support with MP_REACH_NLRI and MP_UNREACH_NLRI parsing (RFC 4760)
    - IPv6 addresses formatted with zero compression (RFC 5952)
    - Added JSONL output format (`-f jsonl` for single line per message)
    - Removed KV output format
    - Added capability parsing and JSON output for OPEN messages (sent and received)

- 0.0.5
    - Graceful shutdown: sends NOTIFICATION on peer deactivation (CEASE/Administrative Shutdown)
    - NOTIFICATION sent on OPEN validation errors (bad peer ASN, version mismatch, invalid hold time)
    - NOTIFICATION sent on hold timer expiry in all applicable FSM states
    - Added BGP NOTIFICATION error codes (RFC 4271, RFC 4486)
    - Added send_notification() function
    - Added 21 new tests for NOTIFICATION functionality (73 total)

- 0.0.4
    - Security fixes for BGP message parsing (bounds checking, input validation)
    - Fixed byte conversion functions (uint32/uint64 big-endian)
    - Fixed memory leaks in error paths
    - Added test suite (make test)
    - Separate debug and release builds (make vs make debug)

- 0.0.3
    - Supports JSON as an output format
    - JSON becomes default output format
    - Requires jansson JSON library to build

- 0.0.2
    - Begin use of SDS string library for string functions     
    - Change command line argument to provide multiple peers
    - Allow naming of peers
    - Multiple peers are now multi-threaded
    - Added better logging
        
- 0.0.1
    - Initial Release
