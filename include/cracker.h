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

char *crack(struct phdr header, FILE *wordlist, unsigned thread_number, unsigned number_of_keyslots);


struct T	{
	pthread_t id;
	unsigned wordlist_start;
	struct phdr header;
	FILE *wordlist;
	unsigned keyslot;
	char result[1000];
};

void *begin_brute_force(void *thread);

#endif
