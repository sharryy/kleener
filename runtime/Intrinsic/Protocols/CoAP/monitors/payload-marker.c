#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §3 with §4.2):
 *   "The presence of a marker followed by a zero-length payload MUST be
 *    processed as a message format error." A Confirmable message with a format
 *   error MUST be rejected, which "is effected by sending a matching Reset
 *   message": Empty, echoing the Message ID.
 *
 * Probe: attach a dangling payload marker (0xFF with no payload bytes after it)
 * by setting a non-NULL payload pointer with payload_length 0; the serializer
 * emits the bare marker. Assert the reply is that Reset; a missing reply is
 * caught by coap_exchange_finalize.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;
static const uint8_t dummy = 0x00;   /* non-NULL sentinel; no bytes are emitted */
static uint16_t request_mid;

void is_coap_payload_marker_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		message->payload = &dummy;       /* non-NULL ... */
		message->payload_length = 0;     /* ... with zero length => bare 0xFF */
		request_mid = message->header.message_id;
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		local_state = DONE;
		assert(message->header.type == COAP_TYPE_RST &&
		       message->header.code == 0 &&
		       message->header.message_id == request_mid &&
		       "SUT did not reject a CON with a dangling payload marker with a "
		       "matching Reset (RFC 7252 3, 4.2 format error)");
	}
}
