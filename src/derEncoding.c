#include "derEncoding.h"

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
int cx_ecfp_encode_sig_der(unsigned char* sig, unsigned int sig_len,
                           unsigned char* r, unsigned int r_len, unsigned char* s, unsigned int s_len) {
    unsigned int offset;

    while ((*r == 0) && r_len) {
        r++;
        r_len--;
    }
    while ((*s == 0) && s_len) {
        s++;
        s_len--;
    }
    if (!r_len || !s_len) {
        return 0;
    }

    //check sig_len
    offset = 3*2+r_len+s_len;
    if (*r&0x80) offset++;
    if (*s&0x80) offset++;
    if (sig_len < offset) {
        return 0;
    }

    //r
    offset = 2;
    if (*r&0x80) {
        sig[offset+2] = 0;
        memmove(sig+offset+3, r, r_len);
        r_len++;
    } else {
        memmove(sig+offset+2, r, r_len);
    }
    sig[offset] = 0x02;
    sig[offset+1] = r_len;

    //s
    offset += 2+r_len;
    if (*s&0x80) {
        sig[offset+2] = 0;
        memmove(sig+offset+3, s, s_len);
        s_len++;
    } else {
        memmove(sig+offset+2, s, s_len);
    }
    sig[offset] = 0x02;
    sig[offset+1] = s_len;

    //head
    sig[0] = 0x30;
    sig[1] = 2+r_len+2+s_len;

    return 2+sig[1];
}

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
static int asn1_read_len(uint8_t **p, const uint8_t *end, size_t *len) {
    /* Adapted from secp256k1 */
    int lenleft;
    unsigned int b1;
    *len = 0;

    if (*p >= end)
        return 0;

    b1 = *((*p)++);
    if (b1 == 0xff) {
        /* X.690-0207 8.1.3.5.c the value 0xFF shall not be used. */
        return 0;
    }
    if ((b1 & 0x80u) == 0) {
        /* X.690-0207 8.1.3.4 short form length octets */
        *len = b1;
        return 1;
    }
    if (b1 == 0x80) {
        /* Indefinite length is not allowed in DER. */
        return 0;
    }
    /* X.690-207 8.1.3.5 long form length octets */
    lenleft = b1 & 0x7Fu;
    if (lenleft > end - *p) {
        return 0;
    }
    if (**p == 0) {
        /* Not the shortest possible length encoding. */
        return 0;
    }
    if ((size_t)lenleft > sizeof(size_t)) {
        /* The resulting length would exceed the range of a size_t, so
         * certainly longer than the passed array size.
         */
        return 0;
    }
    while (lenleft > 0) {
        if ((*len >> ((sizeof(size_t) - 1) * 8)) != 0) {
        }
        *len = (*len << 8u) | **p;
        if (*len + lenleft > (size_t)(end - *p)) {
            /* Result exceeds the length of the passed array. */
            return 0;
        }
        (*p)++;
        lenleft--;
    }
    if (*len < 128) {
        /* Not the shortest possible length encoding. */
        return 0;
    }
    return 1;
}

static int asn1_read_tag(uint8_t **p, const uint8_t *end, size_t *len, int tag) {
    if ((end - *p) < 1) return 0;

    if (**p != tag) return 0;

    (*p)++;
    return asn1_read_len(p, end, len);
}

static int asn1_parse_integer(uint8_t **p, const uint8_t *end, uint8_t **n, size_t *n_len) {
    size_t len;
    int ret = 0;

    if (!asn1_read_tag(p, end, &len, 0x02)) /* INTEGER */
        goto end;

    if (((*p)[0] & 0x80u) == 0x80u) {
        /* Truncated, missing leading 0 (negative number) */
        goto end;
    }

    if ((*p)[0] == 0 && len >= 2 && ((*p)[1] & 0x80u) == 0) {
        /* Zeroes have been prepended to the integer */
        goto end;
    }

    while (**p == 0 && *p != end && len > 0) { /* Skip leading null bytes */
        (*p)++;
        len--;
    }

    *n = *p;
    *n_len = len;

    *p += len;
    ret = 1;

    end:
    return ret;
}

int cx_ecfp_decode_sig_der(const uint8_t *input, size_t input_len,
                           size_t max_size, uint8_t **r, size_t *r_len, uint8_t **s, size_t *s_len) {
    size_t len;
    int ret = 0;
    const uint8_t *input_end = input + input_len;

    uint8_t *p = (uint8_t *)input;

    if (!asn1_read_tag(&p, input_end, &len, 0x30)) /* SEQUENCE */
        goto end;

    if (p + len != input_end) goto end;

    if (!asn1_parse_integer(&p, input_end, r, r_len) ||
        !asn1_parse_integer(&p, input_end, s, s_len))
        goto end;

    if (p != input_end) /* Check if bytes have been appended to the sequence */
        goto end;

    if (*r_len > max_size || *s_len > max_size) {
        return 0;
    }
    ret = 1;
    end:
    return ret;
}

// src must hold a valid DER encoded signature and dest must be allocated exactly 64 bytes.
int cx_ecfp_decode_sig_der_zilliqa (uint8_t *src, uint8_t *dest) {

    int sig_len, r_offset, r_len, s_offset, s_len; 

    // clear dest.
    os_memset(dest, 0, 64);

    sig_len  = src[1]+2;
    r_offset = 4;
    r_len    = src[3];
    s_offset = 4+r_len+2;
    s_len    = src[4+r_len+1];
    if (src[0]  != 0x30 ||
        sig_len != r_len+s_len+6 ||
        src[r_offset-2] != 0x02  || 
        src[s_offset-2] != 0x02  )
        // TODO: Throw error
        return 1;

    //TODO Double check this condition
    if(src[r_offset] == 0x00 && src[r_offset+1] >= 0x8d)
        memcpy(dest, src+r_offset+1, r_len-1);
    else
        memcpy(dest, src+r_offset, r_len);

    
    //TODO Double check this condition
    if(src[s_offset] == 0x00 && src[s_offset+1] >= 0x8d)
        memcpy(dest+32, src+s_offset+1, s_len-1);
    else
        memcpy(dest+32, src+s_offset, s_len);
   
    return 0;
}