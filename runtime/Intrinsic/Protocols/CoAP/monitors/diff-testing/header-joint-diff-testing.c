/* Diff-testing monitor: makes request Version, Type, Token Length and Code symbolic, records the response. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;

void header_joint_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT)
    {
        kleener_make_symbolic(&message->header.version, sizeof(message->header.version), "coap_req_version");
        kleener_make_symbolic(&message->header.type, sizeof(message->header.type), "coap_req_type");
        kleener_make_symbolic(&message->header.token_length, sizeof(message->header.token_length), "coap_req_token_length");
        kleener_make_symbolic(&message->header.code, sizeof(message->header.code), "coap_req_code");
        klee_assume(message->header.version < 4);
        klee_assume(message->header.type < 4);
        klee_assume(message->header.token_length < 16);
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output(message);
        local_state = DONE;
    }
}
