#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include "txn.h"

void txn_init(txn_state_t *txn, uint16_t sigIndex, bool asicChain) {}

void txn_update(txn_state_t *txn, uint8_t *in, uint8_t inlen) {}

txnDecoderState_e txn_next_elem(txn_state_t *txn) { return TXN_STATE_ERR; }
