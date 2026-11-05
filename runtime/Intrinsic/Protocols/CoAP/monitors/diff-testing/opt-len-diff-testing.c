/* Diff-testing monitors: one appended option with a fully symbolic length
 * (0..255); one entry per RFC 7252 Table 4 option, proxy/ETag/Size1 excluded.
 * Uri-Query has its own monitor (uri-query-len-diff-testing.c). */

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

static void opt_len_diff_testing(CoapMessage *message,
                                    bool is_message_client_generated,
                                    uint16_t number) {
  if (is_message_client_generated && local_state == INIT &&
      message->num_options < COAP_MAX_OPTIONS_LENGTH) {
    uint8_t len;
    size_t last = message->num_options;
    size_t i;

    for (i = 0; i < VALUE_MAX; i++)
      opt_value[i] = 'a';

    kleener_make_symbolic(&len, sizeof(len), "coap_opt_len");

    message->options[last].number = number;
    message->options[last].length = len;
    message->options[last].value = opt_value;
    message->num_options = last + 1;
    local_state = INJECTED;
  } else if (!is_message_client_generated && local_state == INJECTED) {
    generate_coap_output(message);
    local_state = DONE;
  }
}

void opt_len_if_match_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 1); }
void opt_len_uri_host_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 3); }
void opt_len_if_none_match_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 5); }
void opt_len_uri_port_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 7); }
void opt_len_location_path_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 8); }
void opt_len_uri_path_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 11); }
void opt_len_content_format_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 12); }
void opt_len_max_age_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 14); }
void opt_len_accept_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 17); }
void opt_len_location_query_diff_testing_server(CoapMessage *m, bool c) { opt_len_diff_testing(m, c, 20); }
