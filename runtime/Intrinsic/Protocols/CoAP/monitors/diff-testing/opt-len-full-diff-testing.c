/* Diff-testing monitor: one appended Uri-Query with a fully symbolic length
 * over the whole range RFC 7252 Table 4 declares for it (0..255). */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT 0
#define INJECTED 1
#define DONE 2
#define VALUE_MAX 255

static int local_state = INIT;
static uint8_t opt_value[VALUE_MAX];

void opt_len_full_diff_testing_server(CoapMessage *message,
                                      bool is_message_client_generated) {
  if (is_message_client_generated && local_state == INIT &&
      message->num_options < COAP_MAX_OPTIONS_LENGTH) {
    uint8_t len;
    size_t last = message->num_options;
    size_t i;

    for (i = 0; i < VALUE_MAX; i++)
      opt_value[i] = 'a';

    kleener_make_symbolic(&len, sizeof(len), "coap_opt_len");
    klee_assume(len <= VALUE_MAX);

    message->options[last].number = 15; /* Uri-Query, declared range 0..255 */
    message->options[last].length = len;
    message->options[last].value = opt_value;
    message->num_options = last + 1;
    local_state = INJECTED;
  } else if (!is_message_client_generated && local_state == INJECTED) {
    generate_coap_output(message);
    local_state = DONE;
  }
}
