/* C-045 — clean detector mirror for native frame-length handling */
/* One validated canonical length controls both allocation and copy. */

if (frame_remaining(frame, 0) < 4) return PARSE_TRUNCATED;
uint32_t wire_len = read_be32(frame);
if (wire_len == 0 || (uintmax_t)wire_len > SIZE_MAX ||
    wire_len > frame_remaining(frame, 4)) {
    return PARSE_INVALID_LENGTH;
}
size_t len = (size_t)wire_len;
uint8_t *out = malloc(len);
if (out == NULL) return PARSE_NO_MEMORY;
memcpy(out, frame + 4, len);
