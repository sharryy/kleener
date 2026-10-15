/* Diff-testing monitor: appends one option with symbolic number, length (0..3) and value bytes, records the response. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

#define OPT_MAX_NUMBER 300
#define OPT_MAX_LEN    3

static int local_state = INIT;
static uint8_t opt_value[OPT_MAX_LEN];

/* Fork the symbolic length into concrete values so the serializer copies a concrete size. */
static uint16_t concrete_len(uint8_t len)
{
    if (len == 0) return 0;
    if (len == 1) return 1;
    if (len == 2) return 2;
    return 3;
}

void option_joint_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT && message->num_options < COAP_MAX_OPTIONS_LENGTH)
    {
        uint16_t number;
        uint8_t len;
        size_t last = message->num_options;
        uint16_t prev = last ? message->options[last - 1].number : 0;

        kleener_make_symbolic(&number, sizeof(number), "coap_opt_number");
        kleener_make_symbolic(&len, sizeof(len), "coap_opt_len");
        kleener_make_symbolic(opt_value, sizeof(opt_value), "coap_opt_value");
        klee_assume(number >= prev);
        klee_assume(number <= OPT_MAX_NUMBER);
        klee_assume(len <= OPT_MAX_LEN);

        message->options[last].number = number;
        message->options[last].length = concrete_len(len);
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
