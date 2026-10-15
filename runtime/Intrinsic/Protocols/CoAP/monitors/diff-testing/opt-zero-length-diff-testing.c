/* Diff-testing monitor: one appended string option x length 0 or 1. RFC 7252 Table 4
 * gives all three options a 0..255 length, so every cell is a valid request. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;
static uint8_t opt_value[1] = {'a'};

/* All three are repeatable with a 0..255 range, and all >= the harness request's
 * Uri-Path (11) so the delta encoding stays monotonic. */
static uint16_t concrete_number(uint8_t sel)
{
    switch (sel)
    {
        case 0:  return 11;   /* Uri-Path, critical */
        case 1:  return 15;   /* Uri-Query, critical */
        default: return 20;   /* Location-Query, elective */
    }
}

/* Concrete so the serializer sees a constant length on each path. */
static uint16_t concrete_length(uint8_t sel)
{
    switch (sel)
    {
        case 0:  return 0;
        default: return 1;
    }
}

void opt_zero_length_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT && message->num_options < COAP_MAX_OPTIONS_LENGTH)
    {
        uint8_t nsel, lsel;
        size_t last = message->num_options;
        uint16_t number;

        kleener_make_symbolic(&nsel, sizeof(nsel), "coap_opt_number_sel");
        kleener_make_symbolic(&lsel, sizeof(lsel), "coap_opt_len_sel");
        klee_assume(nsel <= 2);
        klee_assume(lsel <= 1);

        number = concrete_number(nsel);
        if (last && number < message->options[last - 1].number)
            number = message->options[last - 1].number;

        message->options[last].number = number;
        message->options[last].length = concrete_length(lsel);
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
