/* CoAP monitor dispatcher.
 *
 * The contract is:
 *
 *   handle_coap_message(in, in_size, out, out_size, is_client_originated, monitor)
 *
 * 1. Parse `in` into a mutable CoapMessage `msg` AND an immutable shadow
 *    (concrete sizes used by the serializer when the live message's
 *    fields go symbolic).
 * 2. Invoke `monitor.handle(&msg, is_client_originated)`. The monitor
 *    makes one field of `msg` symbolic and records the response.
 * 3. Serialize the (possibly mutated) `msg` back into `out`. The SUT
 *    then parses `out` — so byte-level mutations made by the monitor
 *    actually reach libcoap, not just our framework's view.
 */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

coap_monitor_handle set_coap_monitor_handle(int experiment, SIDE side_to_check)
{
    static const struct entry {
        coap_monitor_handle server_mon;
        coap_monitor_handle client_mon;
    } table[] = {
        [coap_normal_execution]              = {NULL, NULL},
        /* Differential-testing recording monitors (IDs from 100). Server-side
         * only: each drives both directions internally via the
         * is_message_client_generated flag, so the client slot stays NULL. */
        [coap_code_diff_test]                   = {code_diff_testing_server,        NULL},
        [coap_version_diff_test]                = {version_diff_testing_server,      NULL},
        [coap_type_diff_test]                   = {type_diff_testing_server,         NULL},
        [coap_token_length_diff_test]           = {token_length_diff_testing_server, NULL},
        [coap_mid_diff_test]                    = {mid_diff_testing_server,          NULL},
        [coap_type_code_diff_test]              = {type_code_diff_testing_server,    NULL},
        [coap_token_diff_test]                  = {token_diff_testing_server,           NULL},
        [coap_opt_number_diff_test] = {opt_number_diff_testing_server, NULL},
        [coap_dup_opt_diff_test] = {dup_opt_diff_testing_server, NULL},
        [coap_uri_query_len_diff_test] = {uri_query_len_diff_testing_server, NULL},
        [coap_opt_len_if_match_diff_test] = {opt_len_if_match_diff_testing_server, NULL},
        [coap_opt_len_uri_host_diff_test] = {opt_len_uri_host_diff_testing_server, NULL},
        [coap_opt_len_if_none_match_diff_test] = {opt_len_if_none_match_diff_testing_server, NULL},
        [coap_opt_len_uri_port_diff_test] = {opt_len_uri_port_diff_testing_server, NULL},
        [coap_opt_len_location_path_diff_test] = {opt_len_location_path_diff_testing_server, NULL},
        [coap_opt_len_uri_path_diff_test] = {opt_len_uri_path_diff_testing_server, NULL},
        [coap_opt_len_content_format_diff_test] = {opt_len_content_format_diff_testing_server, NULL},
        [coap_opt_len_max_age_diff_test] = {opt_len_max_age_diff_testing_server, NULL},
        [coap_opt_len_accept_diff_test] = {opt_len_accept_diff_testing_server, NULL},
        [coap_opt_len_location_query_diff_test] = {opt_len_location_query_diff_testing_server, NULL},
    };

    if (experiment < 0 || experiment >= (int)(sizeof(table) / sizeof(table[0])))
        return NULL;

    const struct entry *e = &table[experiment];
    if (side_to_check == CLIENT) return e->client_mon;
    if (side_to_check == SERVER) return e->server_mon;
    return e->server_mon;
}

int handle_coap_message(const uint8_t *in, size_t in_size,
                        uint8_t *out, size_t out_size,
                        bool is_client_originated,
                        COAP_MONITOR mon)
{
    CoapMessage msg;
    CoapMessage shadow;

    memset(&msg,    0, sizeof(msg));
    memset(&shadow, 0, sizeof(shadow));

    if (parse_coap_message(in, in_size, &msg) != 0)
        return -1;
    if (parse_coap_message(in, in_size, &shadow) != 0)
        return -1;

    if (mon.handle != NULL)
        mon.handle(&msg, is_client_originated);

    /* Return the number of bytes written to `out` — the monitor may have
     * resized the message — or -1 on parse/serialize failure. */
    return serialize_coap_message(&msg, &shadow, out, out_size);
}
