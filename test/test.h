#ifndef _MZ_TEST_H
#define _MZ_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

void test_stream_bzip(void);
void test_stream_pkcrypt(void);
void test_stream_wzaes(void);
void test_stream_zlib(void);
void test_stream_mem(void);
void test_stream_find(void);
void test_stream_find_reverse(void);

void test_crypt_sha(void);
void test_crypt_aes(void);
void test_crypt_hmac(void);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif