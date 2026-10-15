#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §5.4.5 with §5.4.1):
 *   "If a message includes an option with more occurrences than the option is
 *    defined for, each supernumerary option occurrence that appears
 *    subsequently in the message MUST be treated like an unrecognized option"
 *   and "unrecognized options of class 'elective' MUST be silently ignored."
 *
 * Probe: append Content-Format (option 12 — even, so elective; not repeatable)
 * twice with a valid 1-byte value. The second occurrence must be ignored and the
 * request served (2.05 here). Answering 4.02 Bad Option applies the critical
 * reaction to an elective option.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;
static const uint8_t cf_value[1] = {0x00};

void is_coap_dup_elective_option_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		size_t pos = message->num_options;
		if (pos + 2 <= COAP_MAX_OPTIONS_LENGTH)
		{
			uint16_t last_number = (pos > 0) ? message->options[pos - 1].number : 0;
			uint16_t number = COAP_OPTION_CONTENT_FORMAT;
			/* Keep the number monotonic and even (elective = bit 0 clear). */
			if (last_number >= number) number = (uint16_t)((last_number + 2) & ~1u);

			message->options[pos].number     = number;
			message->options[pos].length     = sizeof(cf_value);
			message->options[pos].value      = cf_value;
			message->options[pos + 1].number = number;   /* supernumerary occurrence */
			message->options[pos + 1].length = sizeof(cf_value);
			message->options[pos + 1].value  = cf_value;
			message->num_options = pos + 2;
		}
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		local_state = DONE;
		assert(((unsigned)(message->header.code >> 5) == 2) &&
		       "SUT did not ignore a repeated elective option (RFC 7252 5.4.5 + "
		       "5.4.1 require treating it as an unrecognized elective option)");
	}
}
