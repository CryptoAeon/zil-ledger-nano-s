#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "derEncoding.h"
#include "zilliqa.h"

uint8_t * getKeySeed(uint32_t index) {
    static uint8_t keySeed[32];

    // bip32 path for 44'/313'/n'/0'/0'
    // 313 0x80000139 ZIL Zilliqa
    uint32_t bip32Path[] = {44 | 0x80000000,
                            313 | 0x80000000,
                            index | 0x80000000,
                            0x80000000,
                            0x80000000};

    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, bip32Path, 5, keySeed, NULL);
    PRINTF("keySeed: %.*H \n", 32, keySeed);
    return keySeed;
}

void compressPubKey(cx_ecfp_public_key_t *publicKey) {
    // Uncompressed key has 0x04 + X (32 bytes) + Y (32 bytes).
    if (publicKey->W_len != 65 || publicKey->W[0] != 0x04) {
        PRINTF("compressPubKey: Input public key is incorrect\n");
        THROW(SW_INVALID_PARAM);
    }

    // check if Y is even or odd. Assuming big-endian, just check the last byte.
    if (publicKey->W[64] % 2 == 0) {
        // Even
        publicKey->W[0] = 0x02;
    } else {
        // Odd
        publicKey->W[0] = 0x03;
    }

    publicKey->W_len = 33;
}

void deriveZilKeyPair(uint32_t index,
                      cx_ecfp_private_key_t *privateKey,
                      cx_ecfp_public_key_t *publicKey) {
    cx_ecfp_private_key_t pk;
    uint8_t *keySeed = getKeySeed(index);

    cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, 32, &pk);

    if (publicKey) {
        cx_ecfp_init_public_key(CX_CURVE_SECP256K1, NULL, 0, publicKey);
        cx_ecfp_generate_pair(CX_CURVE_SECP256K1, publicKey, &pk, 1);
        PRINTF("publicKey:\n %.*H \n\n", publicKey->W_len, publicKey->W);
    }
    if (privateKey) {
        *privateKey = pk;
        PRINTF("privateKey:\n %.*H \n\n", pk.d_len, pk.d);
    }

    compressPubKey(publicKey);

    os_memset(keySeed, 0, sizeof(keySeed));
    os_memset(&pk, 0, sizeof(pk));
    P();
}

int deriveAndSign(uint8_t *dst, uint32_t index, const uint8_t *hash, unsigned int hashLen) {
    PRINTF("index: %d\n", index);
    PRINTF("hash: %.*H \n", hashLen, hash);

    uint8_t *keySeed = getKeySeed(index);

    cx_ecfp_private_key_t privateKey;
    cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, 32, &privateKey);
    PRINTF("privateKey: %.*H \n", privateKey.d_len, privateKey.d);

    const uint8_t signature[73];
    unsigned int info = 0;
    int sig_len = cx_ecschnorr_sign(&privateKey,
                      CX_RND_TRNG | CX_ECSCHNORR_Z,
                      CX_SHA256,
                      hash,
                      hashLen,
                      signature,
                      73,
                      &info);
    PRINTF("DER signature: %.*H\n", sig_len, signature);
 
    os_memset(keySeed, 0, sizeof(keySeed));
    os_memset(&privateKey, 0, sizeof(privateKey));

    uint8_t rs[64];
    cx_ecfp_decode_sig_der_zilliqa(signature, rs);
    PRINTF("(r,s) signature: %.*H\n", 64, rs);

    copyArray(dst, 0, rs, 64);

    return 64;
}

void pubkeyToZilAddress(uint8_t *dst, cx_ecfp_public_key_t *publicKey) {
    // 3. Apply SHA2-256 to the pub key
    uint8_t digest[SHA256_HASH_LEN];
    cx_hash_sha256(publicKey->W, publicKey->W_len, digest, SHA256_HASH_LEN);
    PRINTF("sha256: %.*H\n", SHA256_HASH_LEN, digest);

    // LSB 20 bytes of the hash is our address.
    for (unsigned i = 0; i < 20; i++) {
        dst[i] = digest[i+12];
    }
}

void bin2hex(uint8_t *dst, uint8_t *data, uint64_t inlen) {
    static uint8_t const hex[] = "0123456789abcdef";
    for (uint64_t i = 0; i < inlen; i++) {
        dst[2 * i + 0] = hex[(data[i] >> 4) & 0x0F];
        dst[2 * i + 1] = hex[(data[i] >> 0) & 0x0F];
    }
    dst[2 * inlen] = '\0';
}

static uint8_t hexchar2bin (unsigned char c) {
    switch (c)
    {
        case '0': return 0x0;
        case '1': return 0x1;
        case '2': return 0x2;
        case '3': return 0x3;
        case '4': return 0x4;
        case '5': return 0x5;
        case '6': return 0x6;
        case '7': return 0x7;
        case '8': return 0x8;
        case '9': return 0x9;
        case 'a': case 'A': return 0xa;
        case 'b': case 'B': return 0xb;
        case 'c': case 'C': return 0xc;
        case 'd': case 'D': return 0xd;
        case 'e': case 'E': return 0xe;
        case 'f': case 'F': return 0xf;
    default:
        THROW(SW_INVALID_PARAM);
    }
}

// Given a hex string with numhexchar characters, convert it
// to byte sequence and place in "bin" (which must be allocated
// with at least numhexchar/2 bytes already).
void hex2bin(uint8_t *hexstr, unsigned numhexchars, uint8_t *bin) {
    if (numhexchars % 2 != 0 || numhexchars == 0)
        THROW(SW_INVALID_PARAM);

    unsigned hexstr_start = 0;
    if (hexstr[0] == '0' && (hexstr[1] == 'x' || hexstr[1] == 'X')) {
        hexstr_start += 2;
    }

    for (unsigned binidx = 0, idx = 0; idx < numhexchars; idx += 2, binidx++) {
        uint8_t msn = hexchar2bin(hexstr[idx+hexstr_start]);
        msn <<= 4;
        uint8_t lsn = hexchar2bin(hexstr[idx+hexstr_start+1]);
        bin[binidx] = msn | lsn;
    }
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

void copyArray(uint8_t *dst, size_t offset, uint8_t *src, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        dst[offset + i] = src[i];
    }
}