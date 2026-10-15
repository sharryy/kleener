/* Diff-testing monitor: symbolic code x payload shape (none / short / long / dangling marker). */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

#define PAYLOAD_MAX 8

static int local_state = INIT;
static const uint8_t payload_bytes[PAYLOAD_MAX] = {'p','a','y','l','o','a','d','!'};

void payload_joint_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT)
    {
        uint8_t code, shape;

        kleener_make_symbolic(&code,  sizeof(code),  "coap_code");
        kleener_make_symbolic(&shape, sizeof(shape), "coap_payload_shape");
        klee_assume(code <= COAP_CODE_DELETE);
        klee_assume(shape <= 3);

        message->header.code = code;

        /* Fork the shape into concrete sizes so the serializer copies a concrete length. */
        if (shape == 0)
        {
            message->payload = NULL;             /* no marker, no payload */
            message->payload_length = 0;
        }
        else if (shape == 1)
        {
            message->payload = payload_bytes;    /* marker + 1 byte */
            message->payload_length = 1;
        }
        else if (shape == 2)
        {
            message->payload = payload_bytes;    /* marker + 8 bytes */
            message->payload_length = PAYLOAD_MAX;
        }
        else
        {
            message->payload = payload_bytes;    /* dangling marker, zero bytes (RFC 7252 3.1 format error) */
            message->payload_length = 0;
        }
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output(message);
        local_state = DONE;
    }
}
