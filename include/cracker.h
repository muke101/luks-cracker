#ifndef CRACKER_H_
#define CRACKER_H_

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "parser.h"

void crack(struct phdr header);

#endif
