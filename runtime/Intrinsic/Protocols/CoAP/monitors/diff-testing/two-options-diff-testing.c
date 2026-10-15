/* Diff-testing monitor: appends two options, each with symbolic number, length (0..2) and value, records the response. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

#define OPT_MAX_NUMBER 64
#define OPT_MAX_LEN    2

static int local_state = INIT;
static uint8_t opt_value_a[OPT_MAX_LEN];
static uint8_t opt_value_b[OPT_MAX_LEN];

static uint16_t concrete_len(uint8_t len)
{
    if (len == 0) return 0;
    if (len == 1) return 1;
    return 2;
}

void two_options_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT && message->num_options + 2 <= COAP_MAX_OPTIONS_LENGTH)
    {
        uint16_t na, nb;
        uint8_t la, lb;
        size_t last = message->num_options;
        uint16_t prev = last ? message->options[last - 1].number : 0;

        kleener_make_symbolic(&na, sizeof(na), "coap_opt_a_number");
        kleener_make_symbolic(&nb, sizeof(nb), "coap_opt_b_number");
        kleener_make_symbolic(&la, sizeof(la), "coap_opt_a_len");
        kleener_make_symbolic(&lb, sizeof(lb), "coap_opt_b_len");
        kleener_make_symbolic(opt_value_a, sizeof(opt_value_a), "coap_opt_a_value");
        kleener_make_symbolic(opt_value_b, sizeof(opt_value_b), "coap_opt_b_value");
        klee_assume(na >= prev);
        klee_assume(nb >= na);
        klee_assume(nb <= OPT_MAX_NUMBER);
        klee_assume(la <= OPT_MAX_LEN);
        klee_assume(lb <= OPT_MAX_LEN);

        message->options[last].number     = na;
        message->options[last].length     = concrete_len(la);
        message->options[last].value      = opt_value_a;
        message->options[last + 1].number = nb;
        message->options[last + 1].length = concrete_len(lb);
        message->options[last + 1].value  = opt_value_b;
        message->num_options = last + 2;
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output(message);
        local_state = DONE;
    }
}
