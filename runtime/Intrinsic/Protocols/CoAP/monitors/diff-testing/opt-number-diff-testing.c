/* Diff-testing monitor: appends one option with a symbolic number and a 1-byte value, records the response. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;
static const uint8_t opt_value[1] = {0x01};

void opt_number_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT && message->num_options + 1 <= COAP_MAX_OPTIONS_LENGTH)
    {
        uint16_t number;
        size_t last = message->num_options;

        kleener_make_symbolic(&number, sizeof(number), "coap_opt_number");

        message->options[last].number = number;
        message->options[last].length = 1;
        message->options[last].value  = opt_value;
        message->num_options = last + 1;
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output(message);
        local_state = DONE;
    }
}
