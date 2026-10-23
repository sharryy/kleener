/* Diff-testing monitor: makes request Code and the number of the existing Uri-Path option symbolic, records the response. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;

void code_option_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT && message->num_options == 1)
    {
        uint16_t number;

        kleener_make_symbolic(&message->header.code,
                              sizeof(message->header.code),
                              "coap_req_code");
        kleener_make_symbolic(&number,
                              sizeof(number),
                              "coap_opt_number");
        message->options[0].number = number;
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output(message);
        local_state = DONE;
    }
}
