#ifndef CRYPTO_BACKEND_H_
#define CRYPTO_BACKEND_H_

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "parser.h"

void hash(unsigned i, unsigned char *di, unsigned char *pi, size_t len);

void H1(unsigned char *d, size_t n);

void H2(unsigned char *d, size_t n);

void xor(unsigned char *a, unsigned char *b, size_t n);

void af_merge(unsigned char *d, unsigned char *split_key, unsigned key_length, unsigned stripes, unsigned version); 

void strip(char *line);

void derive_key(char *password, size_t password_len, struct phdr header, unsigned keyslot, unsigned char *digest);

void decrypt_blocks(unsigned block_count, unsigned sector_size, unsigned char *iv, unsigned iv_len, unsigned char *derived_key, unsigned char *enc_key, unsigned char *split_key);

int checksum(unsigned char *key, struct phdr header);

#endif
