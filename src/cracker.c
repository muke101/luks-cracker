#include "parser.h"
#include "crypto_backend.h"
#include "cracker.h"

int password_found;

unsigned long count_lines(FILE *fp)	{
	unsigned long i;
	char c;

	for (i=0; fread(&c, sizeof(char), 1, fp);)
		if (c == '\n')
			i++;

	return i;
}

struct keyslot_password *crack(struct phdr header, FILE *wordlist, unsigned thread_number, unsigned number_of_keyslots)	{
	unsigned i, j;
	unsigned long password_number, passwords_per_thread, remainder;
	password_number = count_lines(wordlist);	
	passwords_per_thread = password_number/thread_number; //integer devision, will just mean the last thread takes on a couple more than the others if there are remainders
	remainder = password_number % thread_number;

	struct keyslot_password *passwords = calloc(number_of_keyslots, sizeof(struct keyslot_password));
	struct T threads[thread_number];

	for (i=0; i < number_of_keyslots; i++)	{

		password_found = 0;
		passwords[i].keyslot_index = i;

		for (j=0; j < thread_number; j++)	{
			threads[j].wordlist_start = j*passwords_per_thread;
			threads[j].header = header;
			threads[j].wordlist = wordlist;
			threads[j].step = passwords_per_thread;
			threads[j].keyslot = i;
		}
		threads[--j].step+=remainder;

		for (j=0; j < thread_number; j++)	{
			pthread_create(&(threads[j].id), NULL, begin_brute_force, &(threads[j])); 
		}

		for(j=0; j < thread_number; j++)	{
			pthread_join(threads[j].id, &(threads[j].result));
		}

		for (j=0; j < thread_number; j++)
			if (threads[j].result != NULL)
				passwords[i].password = (char *)threads[j].result;
	}

	return passwords;

}

void *begin_brute_force(void *threadInfo)	{

	unsigned i;
	struct T thread = *((struct T *)threadInfo);
	int keyslot = thread.keyslot;
	struct phdr header = thread.header;
	FILE *fp = thread.wordlist; //create local copy of wordlist file descriptor that each thread edits seperately
	unsigned char *global_key = header.active_key_slots[keyslot]->key_data;
	unsigned split_length = header.active_key_slots[keyslot]->stripes*header.key_length;
	unsigned char enc_key[split_length];
	memcpy(enc_key, global_key, split_length*sizeof(char)); //create local copy of key on the stack that an indivisual thread can read to and write to presumerbly faster, will confirm this later though
	size_t bufsize = 1000;
	char p[bufsize];
	char *password = p;
	unsigned char derived_key[header.key_length];
	unsigned block_count = split_length/SECTOR_SIZE; 
	unsigned iv_len = 16;
	unsigned char iv[iv_len];
	unsigned char split_key[split_length]; 
	unsigned char key_candidate[header.key_length];
	unsigned char payload_iv[iv_len];
	memset(payload_iv, 0, iv_len);
	*(uint64_t *)payload_iv = header.payload_offset;
	printf("%d\n",header.payload_offset);
	
	
	fseek(fp, thread.wordlist_start, SEEK_SET);
	for (i=0; i < thread.step && !password_found; i++)	{
		getline(&password, &bufsize, fp);	
		strip(password);
		derive_key(password, strlen(password), header, keyslot, derived_key); 
		decrypt_blocks(block_count, SECTOR_SIZE, iv, iv_len, derived_key, enc_key, split_key);
		af_merge(key_candidate, split_key, header.key_length, header.active_key_slots[keyslot]->stripes, header.version); 
		if (test_entropy(key_candidate, payload_iv, header.test_data) && checksum(key_candidate, header))	{ //condition will stop evaluating if entropy test fails, so long checksum operation only takes place for very likely password candidates
			password_found = 1;
			unsigned char *successful_password = malloc(strlen(password));
			memcpy(successful_password, password, strlen(password));
			printf("password for keyslot %d found: %s\n", ++keyslot, password);
			pthread_exit((void *)successful_password);
		}
	}

	pthread_exit(NULL);
}
