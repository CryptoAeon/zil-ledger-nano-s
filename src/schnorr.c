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

  //generate random, pick a few extra bytes for better security.
  unsigned char nonce[size+8];
  cx_rng(nonce, size+8);
  cx_math_modm(nonce, size+8, (unsigned WIDE char *) PIC(domain->n), size);
  os_memcpy(T->K, nonce, size);

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
  cx_hash((cx_hash_t*) &(T->H), 0, R, 1+size, NULL, 0);    
  cx_hash((cx_hash_t*) &(T->H), 0, U.pub_key.W, 1+size, NULL, 0);
}

// Partially sign msg and update the schnorr state T.
void zil_ecschnorr_sign_continue
(zil_ecschnorr_t *T, const unsigned char *msg, unsigned int msg_len)
{
  if (msg_len != 0)
    cx_hash((cx_hash_t*) &(T->H), 0, msg, msg_len, NULL, 0);
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

  cx_hash((cx_hash_t*) &(T->H), CX_LAST|CX_NO_REINIT, NULL, 0, R, sizeof(R));
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
