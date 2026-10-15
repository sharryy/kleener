#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §5.4.1):
 *   "Unrecognized options of class 'critical' that occur in a Confirmable request
 *    MUST cause the return of a 4.02 (Bad Option) response. [...] Unrecognized
 *    options of class 'critical' that occur in a Non-confirmable message MUST
 *    cause the message to be rejected (Section 4.3)."
 * §4.3: "Rejecting a Non-confirmable message MAY involve sending a matching
 * Reset message, and apart from the Reset message the rejected message MUST be
 * silently ignored." So the only two conformant reactions are silence and a
 * Reset; an error response such as 4.02 is not a rejection.
 *
 * Probe: the same unknown critical option as the Confirmable case (number 21,
 * odd, unassigned) but with the request type flipped to NON, which the
 * Confirmable-only monitor never reaches. Silence is not observable here (it is
 * caught by coap_exchange_finalize), so judge any response that does arrive.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;

void is_coap_non_critical_option_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		size_t pos = message->num_options;
		if (pos < COAP_MAX_OPTIONS_LENGTH)
		{
			uint16_t last_number = (pos > 0) ? message->options[pos - 1].number : 0;
			uint16_t target = 21;
			if (last_number >= target) target = (uint16_t)((last_number + 1) | 1);

			message->options[pos].number = target;
			message->options[pos].length = 0;
			message->options[pos].value  = NULL;
			message->num_options = pos + 1;
		}
		message->header.type = COAP_TYPE_NON;
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		local_state = DONE;
		assert(message->header.type == COAP_TYPE_RST &&
		       message->header.code == COAP_CODE_EMPTY &&
		       "SUT answered a NON request carrying an unknown critical option "
		       "with something other than Reset (RFC 7252 5.4.1 + 4.3 require "
		       "rejecting it: silence, or a matching Reset)");
	}
}
