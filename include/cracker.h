#ifndef CRACKER_H_
#define CRACKER_H_

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include "parser.h"

void crack(struct phdr header, FILE *wordlistFile, unsigned threads);

struct T	{
	pthread_t id;
	unsigned wordlist_start;
	struct phdr header;
	FILE wordlist;
	char result[1000];
};

#endif
