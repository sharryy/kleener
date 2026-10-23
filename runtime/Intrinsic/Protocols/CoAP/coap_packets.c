#include "klee/Protocols/coap/coap_packets.h"
#include "klee/klee.h"

#include <string.h>
#include <stdio.h>
#include <stddef.h>

/* Decode an extended-form 4-bit nibble (the upper nibble of the option
 * header byte, or the lower nibble) into the full value, consuming extra
 * bytes from `buf` as needed.
 *
 *   nibble 0..12    : value is nibble, no extra bytes
 *   nibble == 13    : value = next 1 byte + 13
 *   nibble == 14    : value = next 2 bytes (big-endian) + 269
 *   nibble == 15    : reserved (payload marker on the delta nibble)
 *
 * Returns the decoded value; writes the number of extra bytes consumed
 * to `*extra_bytes` (0, 1, or 2). On format error (extended form past
 * end of buffer) returns UINT16_MAX and `*extra_bytes` is left -1.
 */
static uint32_t decode_nibble(uint8_t nibble, const uint8_t *buf, size_t avail,
                              int *extra_bytes)
{
    if (nibble <= 12)
    {
        *extra_bytes = 0;
        return nibble;
    }
    if (nibble == COAP_OPTION_NIBBLE_1BYTE_EXT)
    {
        if (avail < 1) { *extra_bytes = -1; return 0; }
        *extra_bytes = 1;
        return (uint32_t)buf[0] + 13u;
    }
    if (nibble == COAP_OPTION_NIBBLE_2BYTE_EXT)
    {
        if (avail < 2) { *extra_bytes = -1; return 0; }
        *extra_bytes = 2;
        return ((uint32_t)buf[0] << 8 | (uint32_t)buf[1]) + 269u;
    }
    /* nibble == 15 — caller must handle separately (payload marker etc.) */
    *extra_bytes = -1;
    return 0;
}

/* Inverse of decode_nibble — pick the nibble (0..14) and any extension
 * bytes needed to encode `value`. Returns the nibble; writes the
 * extension bytes (0, 1, or 2) into `ext_out[0..*ext_len-1]`. */
static uint8_t encode_nibble(uint32_t value, uint8_t *ext_out, int *ext_len)
{
    if (value <= 12) { *ext_len = 0; return (uint8_t)value; }
    if (value <= 268)
    {
        *ext_len   = 1;
        ext_out[0] = (uint8_t)(value - 13);
        return COAP_OPTION_NIBBLE_1BYTE_EXT;
    }
    /* value <= 65804 */
    *ext_len   = 2;
    ext_out[0] = (uint8_t)(((value - 269) >> 8) & 0xFF);
    ext_out[1] = (uint8_t)((value - 269) & 0xFF);
    return COAP_OPTION_NIBBLE_2BYTE_EXT;
}

int parse_coap_message(const uint8_t* buf, size_t data_length, CoapMessage* message)
{
    if (data_length < 4) return -1;

    const uint8_t version = (buf[0] >> 6) & 0x03;
    const uint8_t type = (buf[0] >> 4) & 0x03;
    const uint8_t token_length = buf[0] & 0x0f;
    const uint8_t code = buf[1];
    const uint16_t message_id = ((uint16_t)buf[2] << 8) | buf[3];

    message->header.version = version;
    message->header.type = type;
    message->header.token_length = token_length;
    message->header.code = code;
    message->header.message_id = message_id;
    message->num_options = 0;
    message->payload = NULL;
    message->payload_length = 0;

    if (4 + (size_t)message->header.token_length > data_length)
        return -1;
    if (message->header.token_length > COAP_MAX_TOKEN_LENGTH)
        return -1;

    memcpy(message->token, buf + 4, message->header.token_length);

    /* Options (RFC 7252 §3.1) — delta-encoded TLV after the token. */
    {
        size_t off = 4 + (size_t)message->header.token_length;
        uint16_t running_number = 0;

        while (off < data_length && message->num_options < COAP_MAX_OPTIONS_LENGTH)
        {
            uint8_t hdr;
            uint8_t delta_nibble, length_nibble;
            int delta_ext, length_ext;
            uint32_t delta_val, length_val;

            hdr = buf[off];

            if (hdr == COAP_PAYLOAD_MARKER)
            {
                off += 1;
                /* RFC 7252 §3.1: a payload marker followed by a zero-length
                 * payload MUST be processed as a message format error. */
                if (off >= data_length)
                    return -1;
                message->payload = buf + off;
                message->payload_length = data_length - off;
                return 0;
            }

            off += 1;

            delta_nibble  = (uint8_t)((hdr >> 4) & 0x0F);
            length_nibble = (uint8_t)(hdr & 0x0F);

            if (delta_nibble == COAP_OPTION_NIBBLE_RESERVED ||
                length_nibble == COAP_OPTION_NIBBLE_RESERVED)
                return -1;

            delta_ext = 0; length_ext = 0;
            delta_val  = decode_nibble(delta_nibble,  buf + off,
                                       data_length - off, &delta_ext);
            if (delta_ext < 0) return -1;
            off += (size_t)delta_ext;

            length_val = decode_nibble(length_nibble, buf + off,
                                       data_length - off, &length_ext);
            if (length_ext < 0) return -1;
            off += (size_t)length_ext;

            if (off + length_val > data_length) return -1;

            running_number = (uint16_t)(running_number + delta_val);
            message->options[message->num_options].number = running_number;
            message->options[message->num_options].length = (uint16_t)length_val;
            message->options[message->num_options].value  = buf + off;
            message->num_options += 1;

            off += length_val;
        }
    }

    return 0;
}

/* Rebuilds v bit by bit, so KLEE forks it into concrete values (only the
 * feasible ones); see the byte0 note. */
static uint32_t concrete_bits(uint32_t v, int bits)
{
    uint32_t r = 0;
    int b;

    for (b = bits - 1; b >= 0; b--)
        if (v & (1u << b))
            r |= 1u << b;
    return r;
}

int serialize_coap_message(const CoapMessage *message,
                           const CoapMessage *shadow,
                           uint8_t *out_buf,
                           size_t out_buf_size)
{
    if (out_buf_size < 4) return -1;

    /* Header. Each byte0 field is made concrete per path: a symbolic field
     * shifted into byte0 leaves token_length unfoldable under KLEE, which
     * mis-parses the options and yields a phantom 4.04. */
    out_buf[0] = (uint8_t)((concrete_bits(message->header.version, 2) << 6) |
                           (concrete_bits(message->header.type, 2) << 4) |
                            concrete_bits(message->header.token_length, 4));
    out_buf[1] = message->header.code;
    out_buf[2] = (uint8_t)((message->header.message_id >> 8) & 0xFF);
    out_buf[3] = (uint8_t)( message->header.message_id       & 0xFF);

    {
        size_t out_off = 4;
        const CoapMessage *sizes = (shadow != NULL) ? shadow : message;
        size_t tkl = sizes->header.token_length;
        size_t num_opts;
        CoapOption opts[COAP_MAX_OPTIONS_LENGTH];
        uint16_t prev_number = 0;
        size_t i;
        int k;

        /* Token — use shadow's TKL to bound the copy. */
        if (tkl > COAP_MAX_TOKEN_LENGTH) tkl = COAP_MAX_TOKEN_LENGTH;
        if (out_off + tkl > out_buf_size) return -1;
        memcpy(out_buf + out_off, message->token, tkl);
        out_off += tkl;

        /* Options — re-encode using LIVE option numbers (so the monitor's
         * mutations to options[i].number propagate to the wire) but shadow's
         * lengths and value pointers (so a symbolic length doesn't drive the
         * memcpy size). */
        num_opts = message->num_options;
        if (num_opts > COAP_MAX_OPTIONS_LENGTH) num_opts = COAP_MAX_OPTIONS_LENGTH;

        /* For options that existed in the original message use shadow's
         * concrete length+value; for monitor-injected options beyond
         * shadow->num_options use the live values the monitor set. */
        for (i = 0; i < num_opts; i++)
        {
            const CoapOption *src = (i < sizes->num_options) ? &sizes->options[i]
                                                             : &message->options[i];
            opts[i].number = message->options[i].number;
            opts[i].length = src->length;
            opts[i].value  = src->value;
        }

        /* Stable sort by number: deltas must be non-negative (RFC 7252 3.1). */
        for (i = 1; i < num_opts; i++)
        {
            CoapOption cur = opts[i];
            size_t j = i;
            while (j > 0 && opts[j - 1].number > cur.number)
            {
                opts[j] = opts[j - 1];
                j--;
            }
            opts[j] = cur;
        }

        for (i = 0; i < num_opts; i++)
        {
            uint32_t delta  = (uint32_t)(opts[i].number - prev_number);
            const CoapOption *src = &opts[i];
            /* A symbolic length would move every later byte to a symbolic offset. */
            uint32_t length = concrete_bits(src->length, 16);
            uint8_t  delta_ext[2], length_ext[2];
            int      delta_ext_len = 0, length_ext_len = 0;
            uint8_t  delta_nibble  = encode_nibble(delta,  delta_ext,  &delta_ext_len);
            uint8_t  length_nibble = encode_nibble(length, length_ext, &length_ext_len);

            if (out_off + 1 + (size_t)delta_ext_len + (size_t)length_ext_len + length
                > out_buf_size) return -1;

            out_buf[out_off++] = (uint8_t)((concrete_bits(delta_nibble, 4) << 4) |
                                           concrete_bits(length_nibble, 4));
            for (k = 0; k < delta_ext_len;  k++) out_buf[out_off++] = delta_ext[k];
            for (k = 0; k < length_ext_len; k++) out_buf[out_off++] = length_ext[k];
            if (length > 0 && src->value != NULL)
            {
                memcpy(out_buf + out_off, src->value, length);
                out_off += length;
            }

            prev_number = opts[i].number;
        }

        /* Malformed case (RFC 7252 §3.1): a monitor can request a bare payload
         * marker with a zero-length payload — which MUST be a message format
         * error — by setting the LIVE message's payload to non-NULL with
         * payload_length 0. Driven from the live message (not shadow) so the
         * monitor's injection reaches the wire; normal traffic has payload==NULL
         * here and is unaffected. */
        if (message->payload != NULL && message->payload_length == 0)
        {
            if (out_off + 1 > out_buf_size) return -1;
            out_buf[out_off++] = COAP_PAYLOAD_MARKER;   /* dangling marker, no bytes */
        }
        /* Monitor-injected payload where the request carried none: driven from
         * the live message (shadow has no payload to copy). */
        else if (message->payload != NULL && sizes->payload == NULL &&
                 message->payload_length > 0)
        {
            if (out_off + 1 + message->payload_length > out_buf_size) return -1;
            out_buf[out_off++] = COAP_PAYLOAD_MARKER;
            memcpy(out_buf + out_off, message->payload, message->payload_length);
            out_off += message->payload_length;
        }
        /* Payload — bring across verbatim from shadow. */
        else if (sizes->payload != NULL && sizes->payload_length > 0)
        {
            if (out_off + 1 + sizes->payload_length > out_buf_size) return -1;
            out_buf[out_off++] = COAP_PAYLOAD_MARKER;
            memcpy(out_buf + out_off, sizes->payload, sizes->payload_length);
            out_off += sizes->payload_length;
        }

        /* Success: return the number of bytes written (>= 4, the header). A
         * monitor may have grown or shrunk the message, so callers must use
         * this length rather than the input length. */
        return (int)out_off;
    }
}

void generate_coap_output(CoapMessage *message)
{
    /* Schema excludes messageId (each harness seeds its own) and raw bytes. */
    uint8_t  response_version        = message->header.version;
    uint8_t  response_type           = message->header.type;
    uint8_t  response_code           = message->header.code;
    uint8_t  response_token_length   = message->header.token_length;
    uint8_t  response_num_options    = (uint8_t)  message->num_options;
    uint16_t response_payload_length = (uint16_t) message->payload_length;

    klee_print_expr("responseVersion",       response_version,
                    "responseType",          response_type,
                    "responseCode",          response_code,
                    "responseTokenLength",   response_token_length,
                    "responseNumOptions",    response_num_options,
                    "responsePayloadLength", response_payload_length);
}

void generate_coap_output_mid(CoapMessage *message)
{
    /* Same schema as generate_coap_output plus responseMessageId (shared symbolic MID echo check). */
    uint8_t  response_version        = message->header.version;
    uint8_t  response_type           = message->header.type;
    uint8_t  response_code           = message->header.code;
    uint8_t  response_token_length   = message->header.token_length;
    uint8_t  response_num_options    = (uint8_t)  message->num_options;
    uint16_t response_payload_length = (uint16_t) message->payload_length;
    uint16_t response_message_id     = message->header.message_id;

    klee_print_expr("responseVersion",       response_version,
                    "responseType",          response_type,
                    "responseCode",          response_code,
                    "responseTokenLength",   response_token_length,
                    "responseNumOptions",    response_num_options,
                    "responsePayloadLength", response_payload_length,
                    "responseMessageId",     response_message_id);
}
