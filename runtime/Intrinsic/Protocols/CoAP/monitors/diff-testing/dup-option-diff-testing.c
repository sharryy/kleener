/* Diff-testing monitor: the same option number appended twice (RFC 7252 5.4.5 repetition). */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

#define OPT_MAX_NUMBER 64

static int local_state = INIT;
static const uint8_t opt_value[1] = {0x01};

void dup_option_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT && message->num_options + 2 <= COAP_MAX_OPTIONS_LENGTH)
    {
        uint16_t number;
        size_t last = message->num_options;
        uint16_t prev = last ? message->options[last - 1].number : 0;

        kleener_make_symbolic(&number, sizeof(number), "coap_opt_number");
        klee_assume(number >= prev);
        klee_assume(number <= OPT_MAX_NUMBER);

        message->options[last].number     = number;
        message->options[last].length     = 1;
        message->options[last].value      = opt_value;
        message->options[last + 1].number = number;   /* same number -> repetition */
        message->options[last + 1].length = 1;
        message->options[last + 1].value  = opt_value;
        message->num_options = last + 2;
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output(message);
        local_state = DONE;
    }
}
