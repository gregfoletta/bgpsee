# Change Log
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
