#ifndef COAP_MONITORS_H
#define COAP_MONITORS_H

#include <stdbool.h>
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"   /* SIDE enum, which_side_checked */

#define COAP_VERSION 1

/* KLEE_SYMBOLIC_EXPERIMENT 0: no monitor. */
#define coap_normal_execution            0

/* ---- Differential-testing RECORDING monitor IDs ----
 * Also the legal values of KLEE_SYMBOLIC_EXPERIMENT. A recording monitor
 * makes one request field symbolic and records the server's response via
 * generate_coap_output; the verdict is produced offline by the
 * smt-cross-checker, not by an assert. Each monitor names its symbolic field
 * "coap_req_*"; that name MUST match across the two implementation runs, or
 * conjoining their .smt2 constraints ranges over different arrays and means
 * nothing.
 */
#define coap_code_diff_test 100
#define coap_version_diff_test 101
#define coap_type_diff_test 102
#define coap_token_length_diff_test 103
#define coap_mid_diff_test 104
#define coap_type_code_diff_test 105
#define coap_token_diff_test 109

/* ---- Monitor dispatch table ----
 * One monitor handle per (experiment, side); the recording monitors are
 * server-side only.
 */
typedef void (*coap_monitor_handle)(CoapMessage *message, bool is_message_client_generated);

typedef struct
{
    coap_monitor_handle handle;
} COAP_MONITOR;

coap_monitor_handle set_coap_monitor_handle(int experiment, SIDE side_to_check);

/* Parse `in` into a CoapMessage, invoke `mon.handle`, then write the
 * (possibly mutated) message back into `out`.
 * Returns the number of bytes written to `out` (>= 4) on success, or -1 on
 * failure — the monitor may resize the message, so the caller must use this
 * length, not in_size. */
int handle_coap_message(const uint8_t *in, size_t in_size,
                        uint8_t *out, size_t out_size,
                        bool is_client_originated, COAP_MONITOR mon);

/* ---- Differential-testing recording monitors ----
 * Each makes one request field symbolic, then calls generate_coap_output (see
 * coap_packets.h) on the response to record the output schema. */
void code_diff_testing_server(CoapMessage *message, bool is_message_client_generated);
void version_diff_testing_server(CoapMessage *message, bool is_message_client_generated);
void type_diff_testing_server(CoapMessage *message, bool is_message_client_generated);
void token_length_diff_testing_server(CoapMessage *message, bool is_message_client_generated);

/* Makes the request Message ID symbolic (coap_req_mid) and records the response
 * including responseMessageId, to expose divergences in how servers echo the
 * Message ID in their reply (RFC 7252 §4.2). */
void mid_diff_testing_server(CoapMessage *message, bool is_message_client_generated);

/* Makes request type AND code symbolic to explore the type-x-code acceptance
 * matrix (RFC 7252 §§4.1-4.3). */
void type_code_diff_testing_server(CoapMessage *message, bool is_message_client_generated);

/* Request token bytes symbolic, response token recorded (Token Echo, 5.3.1). */
void token_diff_testing_server(CoapMessage *message, bool is_message_client_generated);

#endif
