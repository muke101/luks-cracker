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

struct keyslot_password	{
	unsigned keyslot_index;
	char *password;
};

struct  keyslot_password *crack(struct phdr header, FILE *wordlist, unsigned thread_number, unsigned number_of_keyslots);

struct T	{
	pthread_t id;
	unsigned wordlist_start;
	unsigned step;
	struct phdr header;
	FILE *wordlist;
	unsigned keyslot;
	void *result;
};

void *begin_brute_force(void *thread);

#endif
