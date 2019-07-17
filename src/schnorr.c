#include "schnorr.h"
#include "zilliqa.h"

/* ------------------------------------------------------------------------ */
/* ---                            secp256k1                             --- */
/* ------------------------------------------------------------------------ */

static unsigned char const C_cx_secp256k1_a[]  = { 
  // a:  0x00
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static unsigned char const C_cx_secp256k1_b[]  = { 
  //b:  0x07
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
static  unsigned char const C_cx_secp256k1_p []  = { 
  //p:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f};
static unsigned char const C_cx_secp256k1_Hp[]  = {
  //Hp: 0x000000000000000000000000000000000000000000000001000007a2000e90a1
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0xa2, 0x00, 0x0e, 0x90, 0xa1};
static unsigned char const C_cx_secp256k1_Gx[] = { 
  //Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 
  0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
static unsigned char const C_cx_secp256k1_Gy[] = { 
  //Gy:  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 
  0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8};
static unsigned char const C_cx_secp256k1_n[]  = { 
  //n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
static unsigned char const C_cx_secp256k1_Hn[]  = {
  //Hn:0x9d671cd581c69bc5e697f5e45bcd07c6741496c20e7cf878896cf21467d7d140
  0x9d, 0x67, 0x1c, 0xd5, 0x81, 0xc6, 0x9b, 0xc5, 0xe6, 0x97, 0xf5, 0xe4, 0x5b, 0xcd, 0x07, 0xc6,
  0x74, 0x14, 0x96, 0xc2, 0x0e, 0x7c, 0xf8, 0x78, 0x89, 0x6c, 0xf2, 0x14, 0x67, 0xd7, 0xd1, 0x40};
  
#define C_cx_secp256k1_h  1

cx_curve_weierstrass_t const C_cx_secp256k1 = { 
  CX_CURVE_SECP256K1,
  256, 32,
  (unsigned char*)C_cx_secp256k1_p,
  (unsigned char*)C_cx_secp256k1_Hp,
  (unsigned char*)C_cx_secp256k1_Gx, 
  (unsigned char*)C_cx_secp256k1_Gy, 
  (unsigned char*)C_cx_secp256k1_n, 
  (unsigned char*)C_cx_secp256k1_Hn, 
  C_cx_secp256k1_h,
  (unsigned char*)C_cx_secp256k1_a, 
  (unsigned char*)C_cx_secp256k1_b, 
};

// Begin schnorr signing. Initializes the already allocated parameter S.
void zil_ecschnorr_sign_init
(zil_ecschnorr_t *T, const cx_ecfp_private_key_t *pv_key)
{
  cx_curve_weierstrass_t WIDE const *domain = &C_cx_secp256k1;
  unsigned int size = domain->length;

  union {
    unsigned char Q[65];
    cx_ecfp_256_public_key_t  pub_key;
  } U;
  unsigned Q_LEN = sizeof(U.Q);
  unsigned char R[33];

  assert(size==32 && sizeof(T->K) == size);
  assert(pv_key->d_len == size);

  PLOC();

  //https://github.com/Zilliqa/Zilliqa/blob/master/src/libCrypto/Schnorr.cpp
  //https://docs.zilliqa.com/whitepaper.pdf
  // 1. Generate a random k from [1, ..., order-1]
  // 2. Compute the commitment Q = kG, where  G is the base point
  // 3. Compute the challenge r = H(Q, kpub, m) [CME: mod n according to pdf/code, Q and kpub compressed "02|03 x" according to code)
  // 4. If r = 0 mod(order), goto 1
  // 4. Compute s = k - r*kpriv mod(order)
  // 5. If s = 0 goto 1.
  // 5  Signature on m is (r, s)

  //generate random
  cx_math_modm(T->K, size,(unsigned WIDE char *) PIC(domain->n), size);

  //sign
  U.Q[0] = 4;
  os_memmove(U.Q+1,      domain->Gx,size);
  os_memmove(U.Q+1+size, domain->Gy,size);
  cx_ecfp_scalar_mult(domain->curve, U.Q, Q_LEN, T->K, size);

  if ((U.Q[2*size]&1) == 1) {
    R[0] = 0x03;
  } else {
    R[0] = 0x02;      
  }
  os_memmove(R+1, U.Q+1, size),
  cx_ecfp_generate_pair2(domain->curve, &U.pub_key, (cx_ecfp_private_key_t *)pv_key, 1, CX_NONE);
  if ((U.pub_key.W[2*size]&1) == 1) {
    U.pub_key.W[0] = 0x03;
  } else {
    U.pub_key.W[0] = 0x02;
  }
  cx_sha256_init(&(T->H));
  cx_hash(&(T->H), 0, R, 1+size, NULL, 0);    
  cx_hash(&(T->H), 0, U.pub_key.W, 1+size, NULL, 0);
}

// Partially sign msg and update the schnorr state T.
void zil_ecschnorr_sign_continue
(zil_ecschnorr_t *T, const unsigned char *msg, unsigned int msg_len)
{
  if (msg_len != 0)
    cx_hash(&(T->H), 0, msg, msg_len, NULL, 0);
}

// Complete the signing process and return signature.
int zil_ecschnorr_sign_finish(
  zil_ecschnorr_t *T, const cx_ecfp_private_key_t *pv_key,
  unsigned char *sig, unsigned int sig_len)
{
  cx_curve_weierstrass_t WIDE const *domain = &C_cx_secp256k1;
  unsigned int size = domain->length;
  unsigned char R[32];
  unsigned char S[32];

  cx_hash(&(T->H), CX_LAST|CX_NO_REINIT, NULL, 0, R, sizeof(R));
  cx_math_modm(R, size, domain->n, size);
  if (cx_math_is_zero(R, size)) {
    return 0;
  }    
  //s = (k-r*pv_key.d)%n
  cx_math_multm(sig, R, pv_key->d, domain->n, size);
  cx_math_subm(S, T->K, sig, domain->n, size);
  if (cx_math_is_zero(S, size)) {
    return 0;
  }

  // Move the (r,s) signature to the destination.
  os_memmove (sig, R, size);
  os_memmove (sig+size, S, size);

  return 1;
}

// Sign a message in one go.
void zil_ecschnorr_sign(
  const cx_ecfp_private_key_t *pv_key,
  const unsigned char  *msg, unsigned int msg_len,
  unsigned char *sig, unsigned int sig_len) 
{
  const int CX_MAX_TRIES = 100;

  assert(sig_len == SCHNORR_SIG_LEN_RS);

  for (int num_tries = 0; num_tries < CX_MAX_TRIES; num_tries++) {
    zil_ecschnorr_t T;
    zil_ecschnorr_sign_init(&T, pv_key);
    zil_ecschnorr_sign_continue(&T, msg, msg_len);
    if (zil_ecschnorr_sign_finish(&T, pv_key, sig, sig_len))
      return;
  }

  // We ran out of attempts.
  FAIL("Schnorr signature: Number of attempts exceeded");
}

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
int zil_ecschnorr_verify(const cx_ecfp_public_key_t *pu_key,
                        int mode, cx_md_t hashID,
                        const unsigned char *msg, unsigned int msg_len,
                        const unsigned char *sig, unsigned int sig_len) {
  
  cx_curve_weierstrass_t const *domain;
  unsigned int                 size;
  unsigned char               *r, *s;
  size_t                      r_len, s_len;
  unsigned char               R[65];
  unsigned char               Q[65];
  unsigned char               h[32];
  
  unsigned R_LEN = sizeof(R);
  unsigned Q_LEN = sizeof(Q);

  cx_sha256_t H;

  UNUSED(hashID);

  domain = &C_cx_secp256k1;
  size = domain->length; 
  assert(hashID==CX_SHA256);
  assert(size==32);
  // assert(CX_CURVE_RANGE(pu_key->curve,WEIERSTRASS));
  assert(pu_key->W_len == 1+2*size);

  if (!cx_ecfp_decode_sig_der(sig, sig_len, size,
                              &r, &r_len, &s, &s_len)) {
    return 0;
  }

  if (cx_math_is_zero(r,r_len) || cx_math_is_zero(s,s_len)) {
    return 0;
  }
  
  int ok = 0;
  switch(mode&CX_MASK_EC) {


  case CX_ECSCHNORR_Z:
    // The algorithm to check the signature (r, s) on a message m using a public
    // key kpub is as follows
    // 1. Check if r,s is in [1, ..., order-1]
    // 2. Compute Q = sG + r*kpub
    // 3. If Q = O (the neutral point), return 0;
    // 4. r' = H(Q, kpub, m) [CME: mod n and Q and kpub compressed "02|03 x" according to pdf/code]
    // 5. return r' == r

    //r,s is in [1, ..., order-1]
    os_memset(R,0,size);
    os_memmove(R+size-r_len, r, r_len);
    if (cx_math_cmp(R,domain->n,size)>=0) {
      return 0;
    }
    os_memmove(R+size-s_len, s, s_len);
    if (cx_math_cmp(R,domain->n,size)>=0) {
      return 0;
    }

    //  Q = sG + r*kpub
    Q[0] = 4;
    os_memmove(Q+1,      domain->Gx,size);
    os_memmove(Q+1+size, domain->Gy,size);  
    cx_ecfp_scalar_mult(domain->curve, Q, Q_LEN, s, s_len); //sG
    os_memmove(R,      pu_key->W,2*size+1);
    cx_ecfp_scalar_mult(domain->curve, R, R_LEN, r, r_len); //rW    
    cx_ecfp_add_point(domain->curve, Q, Q, R, R_LEN);
    if (Q[0] == 0) {
      return 0;
    }
    //r' = H(Q, kpub, m)
    cx_sha256_init(&H);
    if ((Q[2*size]&1) == 1) {
      Q[0] = 0x03;
    } else {
      Q[0] = 0x02;      
    }
    cx_hash((cx_hash_t *)&H, 0, Q, 1+size, NULL, 0); //Q
    os_memmove(Q,pu_key->W, pu_key->W_len);
    if ((Q[2*size]&1) == 1) {
      Q[0] = 0x03;
    } else {
      Q[0] = 0x02;      
    }
    cx_hash((cx_hash_t *)&H, 0, Q, 1+size, NULL, 0); //kpub
    cx_hash((cx_hash_t *)&H, CX_LAST|CX_NO_REINIT, msg, msg_len, R, sizeof(R)); //m
    cx_math_modm(R, size, domain->n, size);
    //
    os_memset(h,0,size);
    os_memmove(h+size-r_len, r, r_len);
    if (os_memcmp(h,R,size) == 0) {
      ok = 1;
    }
    break;    

    default:
      THROW(INVALID_PARAMETER);
  }
    
  return ok;
}

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
        os_memmove(sig+offset+3, r, r_len);
        r_len++;
    } else {
        os_memmove(sig+offset+2, r, r_len);
    }
    sig[offset] = 0x02;
    sig[offset+1] = r_len;

    //s
    offset += 2+r_len;
    if (*s&0x80) {
        sig[offset+2] = 0;
        os_memmove(sig+offset+3, s, s_len);
        s_len++;
    } else {
        os_memmove(sig+offset+2, s, s_len);
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
        os_memcpy(dest, src+r_offset+1, r_len-1);
    else
        os_memcpy(dest, src+r_offset, r_len);

    
    //TODO Double check this condition
    if(src[s_offset] == 0x00 && src[s_offset+1] >= 0x8d)
        os_memcpy(dest+32, src+s_offset+1, s_len-1);
    else
        os_memcpy(dest+32, src+s_offset, s_len);
   
    return 0;
}