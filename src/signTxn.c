#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "zilliqa.h"
#include "ux.h"

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
		// Derive the secret key and sign the hash, storing the signature in
		// the APDU buffer.
		deriveAndSign(G_io_apdu_buffer, SCHNORR_SIG_LEN_RS, ctx->keyIndex, ctx->msg, ctx->msgLen);
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
	UI_TEXT(0x00, 0, 12, 128, "Compare Hashes:"),
	UI_TEXT(0x00, 0, 26, 128, global.signTxnContext.partialHashStr),
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
		return (ctx->displayIndex == ctx->hexMsgLen - 12) ? NULL : element;
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
		os_memmove(ctx->partialHashStr, ctx->hexMsg + ctx->displayIndex, 12);
		// Re-render the screen.
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < ctx->hexMsgLen-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialHashStr, ctx->hexMsg + ctx->displayIndex, 12);
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

void handleSignTxn(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // Read the key index
	ctx->keyIndex = U4LE(dataBuffer, 0);
    PRINTF("ctx->keyIndex: %d \n", ctx->keyIndex);
	// Read the hash len
	ctx->msgLen = U4LE(dataBuffer, 4);
    PRINTF("ctx->msgLen: %d \n", ctx->msgLen);
	// Read the hash.
	if (ctx->msgLen > sizeof(ctx->msg))
		THROW(SW_INVALID_PARAM);
	os_memmove(ctx->msg, dataBuffer+8, ctx->msgLen);

	// Prepare to display the comparison screen by converting the hash to hex
	// and moving the first 12 characters into the partialHashStr buffer.
	bin2hex(ctx->hexMsg, sizeof(ctx->hexMsg), ctx->msg, ctx->msgLen);
	ctx->hexMsgLen = ctx->msgLen * 2;
	os_memmove(ctx->partialHashStr, ctx->hexMsg, 12);
	ctx->partialHashStr[12] = '\0';
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