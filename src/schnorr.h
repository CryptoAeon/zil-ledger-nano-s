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

void zil_ecschnorr_sign(const cx_ecfp_private_key_t *pv_key,
                      int mode,  cx_md_t hashID,
                      const unsigned char  *msg, unsigned int msg_len,
                      unsigned char *sig, unsigned int sig_len);

int zil_ecschnorr_verify(const cx_ecfp_public_key_t *pu_key,
                        int mode, cx_md_t hashID,
                        const unsigned char *msg, unsigned int msg_len,
                        const unsigned char *sig, unsigned int sig_len);

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
int cx_ecfp_encode_sig_der(unsigned char *sig,
                           unsigned int sig_len,
                           unsigned char *r,
                           unsigned int r_len,
                           unsigned char *s,
                           unsigned int s_len);

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */

int cx_ecfp_decode_sig_der(const uint8_t *input,
                           size_t input_len,
                           size_t max_size,
                           uint8_t **r,
                           size_t *r_len,
                           uint8_t **s,
                           size_t *s_len);

// src must hold a valid DER encoded signature and dest must be allocated exactly 64 bytes.
int cx_ecfp_decode_sig_der_zilliqa (uint8_t *src, uint8_t *dest);