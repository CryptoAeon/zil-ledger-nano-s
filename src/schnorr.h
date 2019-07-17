/*
Copyright 2011-2019, Ledger SAS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//compact sig in strict DER format, ie
// - remove leading zero for pos value,
// - keep one zero for negartive value
//    30 ..  02 05  00 00 01 02 03   02 05 00 00 81 02 03
// => 30 ..  02 03  01 02 03         02 03 00 81 02 03
//

#include <os.h>
#include <cx.h>

typedef struct  {
    cx_sha256_t H;         // partial hash.
    unsigned char K[32];   // Random number.
} zil_ecschnorr_t;

void zil_ecschnorr_sign_init
  (zil_ecschnorr_t *T, const cx_ecfp_private_key_t *pv_key);

void zil_ecschnorr_sign_continue 
  (zil_ecschnorr_t *S, const unsigned char *msg, unsigned int msg_len);

int zil_ecschnorr_sign_finish(
  zil_ecschnorr_t *T, const cx_ecfp_private_key_t *pv_key,
  unsigned char *sig, unsigned int sig_len);

void zil_ecschnorr_sign(
  const cx_ecfp_private_key_t *pv_key,
  const unsigned char  *msg, unsigned int msg_len,
  unsigned char *sig, unsigned int sig_len);
