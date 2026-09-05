/* V-025 — native-and-memory-safety / memory-bounds-and-integer-conversion / High / CWE-681 */
/* Inert detector fixture: a narrowed allocation length is followed by a copy using the original wider length. */

uint32_t wire_len = read_be32(frame);
uint16_t allocation_len = (uint16_t)wire_len;
uint8_t *out = malloc(allocation_len);
memcpy(out, frame + 4, wire_len);
