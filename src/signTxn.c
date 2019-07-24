#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "zilliqa.h"
#include "ux.h"
#include "pb_decode.h"
#include "txn.pb.h"

static signTxnContext_t *ctx = &global.signTxnContext;

// Define the approval screen. This is where the user will confirm that they
// want to sign the hash. This UI layout is very common: a background, two
// buttons, and two lines of text.
//
// Screens are arrays of elements; the order of elements determines the order
// in which they are rendered. Elements cannot be modified at runtime.
static const bagl_element_t ui_signHash_approve[] = {
	// The background; literally a black rectangle. This element must be
	// defined first, so that the other elements render on top of it. Also, if
	// your screen doesn't include a background, it will render directly on
	// top of the previous screen.
	UI_BACKGROUND(),

	// Rejection/approval icons, represented by a cross and a check mark,
	// respectively. The cross will be displayed on the far left of the
	// screen, and the check on the far right, so as to indicate which button
	// corresponds to each action.
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),

	// The two lines of text, which together form a complete sentence:
	//
	//    Sign this Txn
	//    with Key #123?
	//
	// Similar gotchas with signHash.c
	UI_TEXT(0x00, 0, 12, 128, "Sign this Txn"),
	UI_TEXT(0x00, 0, 26, 128, global.signTxnContext.indexStr)
};

static unsigned int ui_signHash_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {

	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		// Send an error code to the computer. The application on the computer
		// should recognize this code and display a "user refused to sign"
		// message instead of a generic error.
		io_exchange_with_code(SW_USER_REJECTED, 0);
		// Return to the main screen.
		ui_idle();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		// store the signature in the APDU buffer.
		os_memcpy(G_io_apdu_buffer, ctx->signature, SCHNORR_SIG_LEN_RS);
		// Send the data in the APDU buffer, along with a special code that
		// indicates approval. 64 is the number of bytes in the response APDU,
		// sans response code.
		io_exchange_with_code(SW_OK, SCHNORR_SIG_LEN_RS);
		// Return to the main screen.
		ui_idle();
		break;
	}
	return 0;
}

// Define the comparison screen. This is where the user will compare the hash
// on their device to the one shown on the computer. This UI is identical to
// the approval screen, but with left/right buttons instead of reject/approve.
static const bagl_element_t ui_signHash_compare[] = {
	UI_BACKGROUND(),

	// Left and right buttons for scrolling the text. The 0x01 and 0x02 are
	// called userids; they allow the preprocessor (below) to know which
	// element it's examining.
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),

	// Two lines of text: a header and the contents of the hash. We will be
	// implementing a fancy scrollable text field, so the second line only
	// needs to hold the currently-visible portion of the hash.
	//
	// Note that the userid of these fields is 0: this is a convention that
	// most apps use to indicate that the element should always be displayed.
	// UI_BACKGROUND() also has userid == 0. And if you revisit the approval
	// screen, you'll see that all of those elements have userid == 0 as well.
	UI_TEXT(0x00, 0, 12, 128, "Compare txn:"),
	UI_TEXT(0x00, 0, 26, 128, global.signTxnContext.partialMsg),
};

// This is a "preprocessor" function that controls which elements of the
// screen are displayed. This function is passed to UX_DISPLAY, which calls it
// on each element of the screen. It should return NULL for elements that
// should not be displayed, and otherwise return the element itself. Elements
// can be identified by their userid.
//
// For the comparison screen, we use the preprocessor to make the scroll
// buttons more intuitive: we only display them if there is more text hidden
// off-screen.
//
// Note that we did not define a preprocessor for the approval screen. This is
// because we always want to display every element of that screen. The
// preprocessor acts a filter that selectively hides elements; since we did
// not want to hide any elements, no preprocessor was necessary.
static const bagl_element_t* ui_prepro_signHash_compare(const bagl_element_t *element) {
	switch (element->component.userid) {
	case 1:
		// 0x01 is the left icon (see screen definition above), so return NULL
		// if we're displaying the beginning of the text.
		return (ctx->displayIndex == 0) ? NULL : element;
	case 2:
		// 0x02 is the right, so return NULL if we're displaying the end of the text.
		return (ctx->displayIndex == ctx->msgLen - 12) ? NULL : element;
	default:
		// Always display all other elements.
		return element;
	}
}

// This is the button handler for the comparison screen. Unlike the approval
// button handler, this handler doesn't send any data to the computer.
static unsigned int ui_signHash_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	switch (button_mask) {
	// The available button mask values are LEFT, RIGHT, EVT_RELEASED, and
	// EVT_FAST. EVT_FAST is set when a button is held for 8 "ticks," i.e.
	// 800ms.
	//
	// The comparison screens in the Zilliqa app allow the user to scroll using
	// the left and right buttons. The user should be able to hold a button
	// and scroll at a constant rate. When the user first presses the left
	// button, we'll hit the LEFT case; after they've held the button for 8
	// ticks, we'll hit the EVT_FAST | LEFT case. Since we want to scroll at a
	// constant rate regardless, we handle both cases identically.
	//
	// Also note that, unlike the approval screen, we don't check for
	// EVT_RELEASED. In fact, when a single button is released, none of the
	// switch cases will be hit, so we'll stop scrolling.
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		// Decrement the displayIndex when the left button is pressed (or held).
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		// Use the displayIndex to recalculate the displayed portion of the
		// text. os_memmove is the Ledger SDK's version of memmove (there is
		// no os_memcpy). In practice, I don't think it matters whether you
		// use os_memmove or the standard memmove from <string.h>.
		os_memmove(ctx->partialMsg, ctx->msg + ctx->displayIndex, 12);
		// Re-render the screen.
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < ctx->msgLen-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialMsg, ctx->msg + ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		// Prepare to display the approval screen by printing the key index
		// into the indexStr buffer. We copy two bytes in the final os_memmove
		// so as to include the terminating '\0' byte for the string.
		os_memmove(ctx->indexStr, "with Key #", 10);
		int n = bin2dec(ctx->indexStr+10, ctx->keyIndex);
		os_memmove(ctx->indexStr+10+n, "?", 2);
		// Note that because the approval screen does not have a preprocessor,
		// we must pass NULL.
		UX_DISPLAY(ui_signHash_approve, NULL);
		break;
	}
	// (The return value of a button handler is irrelevant; it is never
	// checked.)
	return 0;
}

// Append msg to ctx->msg for display. THROW if out of memory.
void append_ctx_msg (const char* msg, int msg_len)
{
	if (ctx->msgLen + msg_len >= sizeof(ctx->msg)) {
		FAIL("Display memory full");
	}
	
	os_memcpy(ctx->msg + ctx->msgLen, msg, msg_len);
	ctx->msgLen += msg_len;
}

bool istream_callback (pb_istream_t *stream, pb_byte_t *buf, size_t count)
{
	StreamData *sd = stream->state;
	int bufNext = 0;

	if (sd->len - sd->nextIdx > 0) {
		// We have some data to spare.
		int copylen = MIN(sd->len - sd->nextIdx, count);
		os_memcpy(buf, sd->buf + sd->nextIdx, copylen);
		count -= copylen;
		bufNext += count;
		sd->nextIdx += copylen;
		PRINTF("Streamed %d bytes of data.\n", copylen);
	}

	if (count > 0) {
		// More data to be streamed, but we've run out. Stream from host.
		PRINTF("Still need to stream %d bytes of data.\n", count);
		assert(sd->len == sd->nextIdx);
		if (sd->hostBytesLeft) {
			io_exchange_with_code(SW_OK, 0);
			uint32_t hostBytesLeftOffset = 0;
			uint32_t txnLenOffset = 4;
			uint32_t dataOffset = 8;

			uint32_t hostBytesLeft = U4LE(G_io_apdu_buffer, hostBytesLeftOffset);
			uint32_t txnLen = U4LE(G_io_apdu_buffer, txnLenOffset);
			PRINTF("istream_callback: txnLen: %d\n", txnLen);
			if (txnLen > TXN_BUF_SIZE) {
				FAIL("Cannot handle large data sent from host");
			}

			// Update and move data to our state.
			sd->len = txnLen;
			os_memcpy(sd->buf, G_io_apdu_buffer + dataOffset, txnLen);
			sd->hostBytesLeft = hostBytesLeft;
			sd->nextIdx = 0;

			// Take care of updating our signature state.
			deriveAndSignContinue(&ctx->ecs, sd->buf, txnLen);

			PRINTF("Making recursive call to stream after io_exchange\n");
			return istream_callback(stream, buf+bufNext, count);
		} else {
			// We need more data but can't fetch again. This is an error.
			FAIL("Ran out of data to stream from host");
		}
	}

	return true;
}

bool decode_callback (pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	char buf[PUB_ADDR_BYTES_LEN]; // This is the maximum size required.
	char bufdisp[PUB_ADDR_BYTES_LEN*2+1];
	assert(ZIL_AMOUNT_GASPRICE_BYTES <= PUB_ADDR_BYTES_LEN);

  int readlen;
	const char* tagread;
	switch (field->tag) {
	case ProtoTransactionCoreInfo_toaddr_tag:
		PRINTF("decode_callback: toaddr\n");
		readlen = PUB_ADDR_BYTES_LEN;
		tagread = "sendto:";
		break;
	case ByteArray_data_tag:
		switch ((int) *arg) {
		case ProtoTransactionCoreInfo_amount_tag:
			PRINTF("decode_callback: amount\n");
			readlen = ZIL_AMOUNT_GASPRICE_BYTES;
			tagread = "amount:";
			break;
		case ProtoTransactionCoreInfo_gasprice_tag:
			PRINTF("decode_callback: gasprice\n");
			readlen = ZIL_AMOUNT_GASPRICE_BYTES;
			tagread = "gasprice:";
			break;
		default:
			PRINTF("decode_callback: arg: %d\n", (int) *arg);
			readlen = 0;
			tagread = "";
			FAIL("Unhandled ByteArray tag.");
		}
		break;
	default:
		PRINTF("decode_callback: %d\n", field->tag);
		readlen = 0;
		tagread = "";
		FAIL("Unhandled transaction element.");
	}

	if (pb_read(stream, (pb_byte_t*) buf, readlen)) {
		PRINTF("decoded bytes: 0x%.*h\n", readlen, buf);
		// Write data for display.
		append_ctx_msg(tagread, strlen(tagread));
		// Convert bytes to hex characters and append '\0'.
		bin2hex((uint8_t*)bufdisp, readlen*2 + 1, (uint8_t*) buf, readlen);
		append_ctx_msg(bufdisp, readlen*2);
		append_ctx_msg(" ", 1);
		PRINTF("pb_read: read %d bytes\n", readlen);
	} else {
		PRINTF("pb_read failed\n");
		return false;
	}

	return true;
}
// Sign the txn, also deserializes parts of it. May call io_exchange multiple times.
// Output: 1. Display message will be populated in ctx->msg.
//         2. Signature will be populated in ctx->sdgnature.
bool sign_deserialize_stream(uint8_t *txn1, int txn1Len, int hostBytesLeft)
{
	// Initialize stream data.
	os_memcpy(ctx->sd.buf, txn1, txn1Len);
	ctx->sd.nextIdx = 0; ctx->sd.len = txn1Len; ctx->sd.hostBytesLeft = hostBytesLeft;
  // Setup the stream.
	pb_istream_t stream = { istream_callback, &ctx->sd, hostBytesLeft + txn1Len, NULL };

	// Initialize the display message.
	ctx->msgLen = 0;
	// Initialize schnorr signing, continue with what we have so far.
	deriveAndSignInit(&ctx->ecs, ctx->keyIndex);
	deriveAndSignContinue(&ctx->ecs, txn1, txn1Len);

	// Initialize protobuf Txn structs.
	ProtoTransactionCoreInfo txn = {};
	// Set callbacks for handling the fields that what we need.
	txn.toaddr.funcs.decode = decode_callback;
	// Since we're using the same callback for amount and gasprice,
	// but the tag for both will be set to "ByteArray", we differentiate with "arg".
	txn.amount.data.funcs.decode = decode_callback;
	txn.amount.data.arg = ProtoTransactionCoreInfo_amount_tag;
	txn.gasprice.data.funcs.decode = decode_callback;
	txn.gasprice.data.arg = ProtoTransactionCoreInfo_gasprice_tag;
	// Start decoding (and signing).
	if (pb_decode(&stream, ProtoTransactionCoreInfo_fields, &txn)) {
		PRINTF ("pb_decode successful\n");
		deriveAndSignFinish(&ctx->ecs, ctx->keyIndex, ctx->signature, SCHNORR_SIG_LEN_RS);
		PRINTF ("sign_deserialize_stream: signature: 0x%.*h\n", SCHNORR_SIG_LEN_RS, ctx->signature);
	} else {
		PRINTF ("pb_decode failed\n");
		return false;
	}

	return true;
}

void handleSignTxn(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	int dataIndexOffset = 0;      // offset for the key index to use
	int dataHostBytesLeftOffset = 4; // offset for integer: is there more data (do io_exhange again)?
	int dataTxnLenOffset = 8;     // offset for integer containing length of current txn
	int dataOffset = 12;          // offset for actual transaction data.

	uint8_t txndata[TXN_BUF_SIZE];
	int txnLen, hostBytesLeft;

    // Read the various integers at the beginning.
	ctx->keyIndex = U4LE(dataBuffer, dataIndexOffset);
	PRINTF("handleSignTxn: keyIndex: %d \n", ctx->keyIndex);
	hostBytesLeft = U4LE(dataBuffer, dataHostBytesLeftOffset);
	PRINTF("handleSignTxn: hostBytesLeft: %d \n", hostBytesLeft);
	txnLen = U4LE(dataBuffer, dataTxnLenOffset);
	PRINTF("handleSignTxn: txnLen: %d\n", txnLen);
	if (txnLen > TXN_BUF_SIZE) {
		FAIL("Cannot handle large data sent from host");
	}

	// Read the (partial) transaction
	os_memmove(txndata, dataBuffer+dataOffset, txnLen);
	// Sign the txn and get message for confirmation display, all in ctx.
	// Signature will not go back to host until message display + approval.
	sign_deserialize_stream(txndata, txnLen, hostBytesLeft);

	// Prepare to display the comparison screen by converting the hash to hex
	// and moving the first 12 characters into the partialMsg buffer.
	os_memmove(ctx->partialMsg, ctx->msg, 12);
	ctx->partialMsg[12] = '\0';
	ctx->displayIndex = 0;

	PRINTF("msg:    %.*H \n", ctx->msgLen, ctx->msg);

	// Call UX_DISPLAY to display the comparison screen, passing the
	// corresponding preprocessor. You might ask: Why doesn't UX_DISPLAY
	// also take the button handler as an argument, instead of using macro
	// magic? To which I can only reply: ¯\_(ツ)_/¯
	UX_DISPLAY(ui_signHash_compare, ui_prepro_signHash_compare);

	// Set the IO_ASYNC_REPLY flag. This flag tells zil_main that we aren't
	// sending data to the computer immediately; we need to wait for a button
	// press first.
	*flags |= IO_ASYNCH_REPLY;
}