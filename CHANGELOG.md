# Change Log
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
