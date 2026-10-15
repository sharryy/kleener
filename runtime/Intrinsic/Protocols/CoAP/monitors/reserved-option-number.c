#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §5.4.1 with §12.2):
 *   Option numbers 0, 128, 132 and 136 are Reserved. The class of an option is
 *   decided by the least significant bit of its number, so all four are
 *   elective, and "unrecognized options of class 'elective' MUST be silently
 *   ignored".
 *
 * Probe: append option 128 with a 1-byte value and require the request to be
 * served as if it were absent.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2
#define COAP_OPTION_RESERVED_128 128

static int local_state = INIT;
static const uint8_t value[1] = {0x01};

void is_coap_reserved_option_number_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		size_t pos = message->num_options;
		if (pos < COAP_MAX_OPTIONS_LENGTH)
		{
			uint16_t last_number = (pos > 0) ? message->options[pos - 1].number : 0;
			uint16_t number = COAP_OPTION_RESERVED_128;
			/* Keep the number monotonic and even (elective = bit 0 clear). */
			if (last_number >= number) number = (uint16_t)((last_number + 2) & ~1u);

			message->options[pos].number = number;
			message->options[pos].length = sizeof(value);
			message->options[pos].value  = value;
			message->num_options = pos + 1;
		}
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		local_state = DONE;
		assert(((unsigned)(message->header.code >> 5) == 2) &&
		       "SUT did not ignore a Reserved (elective) option number "
		       "(RFC 7252 5.4.1: unrecognized elective options are ignored)");
	}
}
