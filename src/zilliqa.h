#ifndef ZIL_NANOS_ZILLIQA_H
#define ZIL_NANOS_ZILLIQA_H

#include "schnorr.h"

// Use Zilliqa's DER decode function for signing?
// (this shouldn't have any functional impact).
#define DER_DECODE_ZILLIQA 0

// MACROS
#define PLOC() PRINTF("\n%s - %s:%d \n", __FILE__, __func__, __LINE__);
#define assert(x) \
    if (x) {} else { PLOC(); PRINTF("Assertion failed\n"); THROW (EXCEPTION); }
#define FAIL(x) \
    { \
        PLOC();\
        PRINTF("Zilliqa ledger app failed: %s\n", x);\
        THROW(EXCEPTION); \
    }

// Constants
#define SHA256_HASH_LEN 32
#define PUB_ADDR_BYTES_LEN 20
#define PUBLIC_KEY_BYTES_LEN 33
// https://github.com/Zilliqa/Zilliqa/wiki/Address-Standard#specification
#define BECH32_ADDRSTR_LEN (3 + 1 + 32 + 6)
#define SCHNORR_SIG_LEN_RS 64
#define ZIL_AMOUNT_GASPRICE_BYTES 16
#define ZIL_MAX_TXN_SIZE 8388608 // 8MB

// exception codes
#define SW_DEVELOPER_ERR 0x6B00
#define SW_INVALID_PARAM 0x6B01
#define SW_IMPROPER_INIT 0x6B02
#define SW_USER_REJECTED 0x6985
#define SW_OK            0x9000

// macros for converting raw bytes to uint64_t
#define U8BE(buf, off) (((uint64_t)(U4BE(buf, off))     << 32) | ((uint64_t)(U4BE(buf, off + 4)) & 0xFFFFFFFF))
#define U8LE(buf, off) (((uint64_t)(U4LE(buf, off + 4)) << 32) | ((uint64_t)(U4LE(buf, off))     & 0xFFFFFFFF))

// FUNCTIONS

// Convert un-compressed zilliqa public key to a compressed form.
void compressPubKey(cx_ecfp_public_key_t *publicKey);

// pubkeyToZilAddress converts a Ledger pubkey to a Zilliqa wallet address.
void pubkeyToZilAddress(uint8_t *dst, cx_ecfp_public_key_t *publicKey);

// deriveZilPubKey derives an Ed25519 key pair from an index and the Ledger
// seed. Returns the public key (private key is not needed).
void deriveZilPubKey(uint32_t index, cx_ecfp_public_key_t *publicKey);

// Three functions to stream the signature process. See deriveAndSign to do in a single operation.
void deriveAndSignInit(zil_ecschnorr_t *T, uint32_t index);
void deriveAndSignContinue(zil_ecschnorr_t *T, const uint8_t *msg, unsigned int msg_len);
int deriveAndSignFinish(zil_ecschnorr_t *T, uint32_t index, unsigned char *dst, unsigned int dst_len);

// deriveAndSign derives an ECFP private key from an user specified index and the Ledger seed,
// and uses it to produce a SCHNORR_SIG_LEN_RS length signature of the provided message
// The key is cleared from memory after signing.
void deriveAndSign(uint8_t *dst, uint32_t dst_len, uint32_t index, const uint8_t *msg, unsigned int msg_len);

// BYTE UTILS

// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(uint8_t *dst, uint64_t dstlen, uint8_t *data, uint64_t inlen);

// bin64b2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin64b2dec(uint8_t *dst, uint32_t dst_len, uint64_t n);

// Given a hex string with numhexchar characters, convert it
// to byte sequence and place in "bin" (which must be allocated
// with at least numhexchar/2 bytes already).
void hex2bin(uint8_t *hexstr, unsigned numhexchars, uint8_t *bin);

// Equivalent to what is there in stdlib.
int strncmp( const char * s1, const char * s2, size_t n );
// Equivalent to what is there in stdlib.
size_t strlen(const char *str);
// Equivalent to what is there in stdlib.
char* strcpy(char *dst, const char *src);


#endif