/* Diff-testing monitor: one appended option, number x length over the nibble-extension
 * boundaries (12/13, 268/269) and the per-option range limits. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

#define VALUE_MAX 600

static int local_state = INIT;
static uint8_t opt_value[VALUE_MAX];

/* Numbers >= the harness request's Uri-Path (11) so the delta encoding stays monotonic:
 * repeated Uri-Path, elective recognized, critical recognized, unknown elective/critical. */
static uint16_t concrete_number(uint8_t sel)
{
    switch (sel)
    {
        case 0:  return 11;   /* Uri-Path, critical, 0..255 */
        case 1:  return 12;   /* Content-Format, elective, 0..2 */
        case 2:  return 14;   /* Max-Age, elective, 0..4 */
        case 3:  return 23;   /* Block2, critical, 0..3 */
        case 4:  return 60;   /* Size1, elective, 0..4 */
        case 5:  return 258;  /* unknown, elective */
        default: return 259;  /* unknown, critical */
    }
}

static uint16_t concrete_length(uint8_t sel)
{
    switch (sel)
    {
        case 0:  return 0;
        case 1:  return 1;
        case 2:  return 12;   /* last length that fits the nibble */
        case 3:  return 13;   /* first 1-byte extension */
        case 4:  return 14;
        case 5:  return 255;  /* last length a string option may carry */
        case 6:  return 256;
        case 7:  return 268;  /* last 1-byte extension */
        case 8:  return 269;  /* first 2-byte extension */
        case 9:  return 270;
        default: return VALUE_MAX;
    }
}

void opt_len_boundary_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT && message->num_options < COAP_MAX_OPTIONS_LENGTH)
    {
        uint8_t nsel, lsel;
        size_t last = message->num_options;
        uint16_t number;
        size_t i;

        for (i = 0; i < VALUE_MAX; i++) opt_value[i] = 'A';

        kleener_make_symbolic(&nsel, sizeof(nsel), "coap_opt_number_sel");
        kleener_make_symbolic(&lsel, sizeof(lsel), "coap_opt_len_sel");
        klee_assume(nsel <= 6);
        klee_assume(lsel <= 10);

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
