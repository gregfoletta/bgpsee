# Change Log
- 0.0.4
    - Parsing of OPEN message capabilities
    - Better ingress queueing
    - Removal of key=value output; JSON is currently the only supported format
    - Added parsing of AS4_PATH and AS4_AGGREGATOR path attributes
    - Outpput of type and type code for all path attributes in an UPDATE
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
