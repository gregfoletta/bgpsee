#include <stdint.h>

char *parameter_string(uint8_t);
char *capability_string(uint8_t);

//Address Family Identifiers
char *afi_string(uint16_t);
char *safi_string(uint8_t);

//Path Attributes
char *pa_flag_optional_string(uint8_t flag);
char *pa_flag_transitive_string(uint8_t flag);
char *pa_flag_partial_string(uint8_t flag);
char *pa_flag_extended_string(uint8_t flag);
