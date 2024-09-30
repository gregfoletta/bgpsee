#include <stdint.h>

struct tlv;

struct tlv *new_tlv(uint8_t, uint8_t, uint8_t *);
int free_tlv(struct tlv *);
unsigned char *serialise_tlv(struct tlv *tlv, uint8_t *);
uint8_t serialise_tlv_buffer(struct tlv *, unsigned char **);

