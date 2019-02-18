#ifndef ZIL_NANOS_TXN_H
#define ZIL_NANOS_TXN_H

// ENUMS
// txnDecoderState_e indicates a transaction decoder status
typedef enum {
    TXN_STATE_ERR = 1,  // invalid transaction (NOTE: it's illegal to THROW(0))
    TXN_STATE_PARTIAL,  // no elements have been fully decoded yet
    TXN_STATE_READY,    // at least one element is fully decoded
    TXN_STATE_FINISHED, // reached end of transaction
} txnDecoderState_e;

// txnElemType_e indicates a transaction element type.
typedef enum {
    TXN_ELEM_SC_INPUT,
    TXN_ELEM_ZIL_OUTPUT,
    TXN_ELEM_FC,
    TXN_ELEM_FCR,
    TXN_ELEM_SP,
    TXN_ELEM_SF_INPUT,
    TXN_ELEM_SF_OUTPUT,
    TXN_ELEM_MINER_FEE,
    TXN_ELEM_ARB_DATA,
    TXN_ELEM_TXN_SIG,
} txnElemType_e;

// txn_state_t is a helper object for computing the SigHash of a streamed
// transaction.
typedef struct {
    uint8_t buf[510]; // holds raw tx bytes; large enough for two 0xFF reads
    uint16_t buflen;  // number of valid bytes in buf
    uint16_t pos;     // mid-decode offset; reset to 0 after each elem

    txnElemType_e elemType; // type of most-recently-seen element
    uint64_t sliceLen;      // most-recently-seen slice length prefix
    uint16_t sliceIndex;    // offset within current element slice

    uint16_t sigIndex;   // index of TxnSig being computed
    bool asicChain;      // apply ASIC hardfork replay protection
    cx_blake2b_t blake;  // hash state
    uint8_t sigHash[32]; // buffer to hold final hash

    uint8_t outVal[128]; // most-recently-seen currency value, in decimal
    uint8_t valLen;      // length of outVal
    uint8_t outAddr[77]; // most-recently-seen address
} txn_state_t;

// FUNCTIONS
// txn_init initializes a transaction decoder, preparing it to calculate the
// requested SigHash.
void txn_init(txn_state_t *txn, uint16_t sigIndex, bool asicChain);

// txn_update adds data to a transaction decoder.
void txn_update(txn_state_t *txn, uint8_t *in, uint8_t inlen);

// txn_next_elem decodes the next element of the transaction. If the element
// is ready for display, txn_next_elem returns TXN_STATE_READY. If more data
// is required, it returns TXN_STATE_PARTIAL. If a decoding error is
// encountered, it returns TXN_STATE_ERR. If the transaction has been fully
// decoded, it returns TXN_STATE_FINISHED.
txnDecoderState_e txn_next_elem(txn_state_t *txn);

#endif