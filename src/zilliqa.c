#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "zilliqa.h"

void deriveZilKeyPair(uint32_t index,
                      cx_ecfp_private_key_t *privateKey,
                      cx_ecfp_public_key_t *publicKey) {
    uint8_t keySeed[32];
    cx_ecfp_private_key_t pk;

    //313 	0x80000139 	ZIL 	Zilliqa
    // bip32 path for 44'/313'/n'/0'/0'
    uint32_t bip32Path[] = {44 | 0x80000000,
                            313 | 0x80000000,
                            index | 0x80000000,
                            0x80000000,
                            0x80000000};
    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, bip32Path, 5, keySeed, NULL);
    PRINTF("keySeed:\n %.*H \n", 32, keySeed);
    cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, sizeof(keySeed), &pk);

    if (publicKey) {
        cx_ecfp_init_public_key(CX_CURVE_SECP256K1, NULL, 0, publicKey);
        PRINTF("publicKey:\n %.*H \n", publicKey->W_len, publicKey->W);
        cx_ecfp_generate_pair(CX_CURVE_SECP256K1, publicKey, &pk, 1);
    }
    if (privateKey) {
        *privateKey = pk;
        PRINTF("privateKey:\n %.*H \n", 32, pk.d);
    }

    os_memset(keySeed, 0, sizeof(keySeed));
    os_memset(&pk, 0, sizeof(pk));
    P();
}

void extractPubkeyBytes(unsigned char *dst, cx_ecfp_public_key_t *publicKey) {
    for (int i = 0; i < 32; i++) {
        dst[i] = publicKey->W[72 - i];
    }
    if (publicKey->W[32] & 1) {
        dst[31] |= 0x80;
    }
}

void deriveAndSign(uint8_t *dst, uint32_t index, const uint8_t *hash) {
    PRINTF("index: %d\n", index);

    //313 	0x80000139 	ZIL 	Zilliqa
    // bip32 path for 44'/313'/n'/0'/0'
    uint32_t bip32Path[] = {44 | 0x80000000,
                            313 | 0x80000000,
                            index | 0x80000000,
                            0x80000000,
                            0x80000000};
    uint8_t keySeed[32];
    P();

    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, bip32Path, 5, keySeed, NULL);
    PRINTF("keySeed:    %.*H \n", 32, keySeed);

    cx_ecfp_private_key_t privateKey;
    cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, sizeof(keySeed), &privateKey);
    PRINTF("privateKey: %.*H \n", 32, privateKey.d);

    unsigned int info = 0;
    cx_ecschnorr_sign(&privateKey,
                      CX_ECSCHNORR_Z,
                      CX_SHA256,
                      hash,
                      32,
                      dst,
                      72,
                      &info);
    PRINTF("signature: %.*H\n", 72, dst);
    PRINTF("info: %d\n", info);
}

void bin2hex(uint8_t *dst, uint8_t *data, uint64_t inlen) {
    static uint8_t const hex[] = "0123456789abcdef";
    for (uint64_t i = 0; i < inlen; i++) {
        dst[2 * i + 0] = hex[(data[i] >> 4) & 0x0F];
        dst[2 * i + 1] = hex[(data[i] >> 0) & 0x0F];
    }
    dst[2 * inlen] = '\0';
}

void pubkeyToZilAddress(uint8_t *dst, cx_ecfp_public_key_t *publicKey) {
    // TODO implement
}

int bin2dec(uint8_t *dst, uint64_t n) {
    if (n == 0) {
        dst[0] = '0';
        dst[1] = '\0';
        return 1;
    }
    // determine final length
    int len = 0;
    for (uint64_t nn = n; nn != 0; nn /= 10) {
        len++;
    }
    // write digits in big-endian order
    for (int i = len - 1; i >= 0; i--) {
        dst[i] = (n % 10) + '0';
        n /= 10;
    }
    dst[len] = '\0';
    return len;
}