#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <string.h>

/* Requirement (CoAP RFC 7252 §5.3.1):
 *   "Every request carries a client-generated token that the server MUST echo
 *    (without modification) in any resulting response."
 *
 * Inject symbolic token bytes while keeping the original TKL; on a response
 * (code class 2/4/5) assert its token equals the injected one. A conformant
 * server echoes verbatim on every path; one that drops or mangles the token
 * fires.
 */

#define INIT     0
#define INJECTED 1

static int     local_state = INIT;
static uint8_t injected_token[COAP_MAX_TOKEN_LENGTH];
static uint8_t injected_tkl;

void is_coap_token_match_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		injected_tkl = message->header.token_length;
		kleener_make_symbolic(message->token, injected_tkl, "monitor_token");
		memcpy(injected_token, message->token, injected_tkl);
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		/* only responses echo the token; an empty ACK or RST carries none */
		uint8_t class = (uint8_t)(message->header.code >> 5);
		if (class != 2 && class != 4 && class != 5)
			return;

		assert(message->header.token_length == injected_tkl &&
		       memcmp(message->token, injected_token, injected_tkl) == 0 &&
		       "SUT response did not echo the request token (RFC 7252 §5.3.1)");
	}
}
