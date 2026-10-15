#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §5.4.3 with §5.4.1):
 *   "The value of an option [...] that does not match the length defined for
 *    that option [...] MUST be treated like an unrecognized option" and
 *   "unrecognized options of class 'elective' MUST be silently ignored."
 *
 * Probe: append Max-Age (option 14 — even, so elective; defined length 0..4)
 * with a 5-byte value. The option is malformed, but because it is elective the
 * server must ignore it and still serve the request (2.05 here). Answering RST
 * or 4.02 applies the critical-option reaction to an elective option.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2
#define COAP_OPTION_MAX_AGE_LEN_BAD 5

static int local_state = INIT;
static const uint8_t bad_max_age[COAP_OPTION_MAX_AGE_LEN_BAD] = {0, 0, 0, 0, 0};

void is_coap_elective_bad_length_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		size_t pos = message->num_options;
		if (pos < COAP_MAX_OPTIONS_LENGTH)
		{
			uint16_t last_number = (pos > 0) ? message->options[pos - 1].number : 0;
			uint16_t number = COAP_OPTION_MAX_AGE;
			/* Keep the number monotonic and even (elective = bit 0 clear). */
			if (last_number >= number) number = (uint16_t)((last_number + 2) & ~1u);

			message->options[pos].number = number;
			message->options[pos].length = sizeof(bad_max_age);
			message->options[pos].value  = bad_max_age;
			message->num_options = pos + 1;
		}
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		local_state = DONE;
		assert(((unsigned)(message->header.code >> 5) == 2) &&
		       "SUT did not ignore an elective option with an out-of-range "
		       "length (RFC 7252 5.4.3 + 5.4.1 require silently ignoring it)");
	}
}
