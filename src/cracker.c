#include "parser.h"
#include "cracker.h"

int passwordFound = 0;

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

		passwords[i].keyslot_index = i;

		for (j=0; j < thread_number; j++)	{
			threads[j].wordlist_start = j*passwords_per_thread;
			threads[j].header = header;
			threads[j].wordlist = wordlist;
			threads[j].step = passwords_per_thread;
			threads[j].keyslot = i;
		}
		threads[--j].step+=remainder;
		printf("hellohello\n");

		for (j=0; j < thread_number; j++)	{
			pthread_create(&(threads[j].id), NULL, begin_brute_force, &(threads[j])); 
		}

		for(j=0; j < thread_number; j++)	{
			pthread_join(threads[j].id, threads[j].result);
		}

		for (j=0; j < thread_number; j++)
			if (threads[j].result != NULL)
				passwords[i].password = (char *)threads[j].result;
	}

	return passwords;

}

void hash(unsigned i, unsigned char *di, unsigned char *pi, size_t len)	{
	i = htobe32(i);
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &i, sizeof(uint32_t));
	SHA256_Update(&ctx, di, len);
	SHA256_Final(pi, &ctx);
}                                                                        

void H1(unsigned char *d, size_t n)	{
	unsigned i;
	size_t digest_size = SHA256_DIGEST_SIZE/8; //not making this portable for non-default hash functions for now
	unsigned char di[digest_size];
	unsigned char pi[digest_size];
	unsigned blocks = n / digest_size;
	unsigned crop = n % digest_size;
	
	for (i=0; i < blocks; i++)	{
		memcpy(di, d+(i*digest_size), digest_size);
		hash(i, di, pi, digest_size);
		memcpy(d+(i*digest_size), pi, digest_size);
	}

	if (crop)	{
		--i;
		memcpy(di, d+(i*digest_size), crop);
		hash(i+1, di, pi, crop);
		memcpy(d+(i*digest_size), pi, crop);
	}
}

void H2(unsigned char *d, size_t n)	{
	int i;
	size_t digest_size = SHA256_DIGEST_SIZE/8;
	unsigned char pi[digest_size];
	int blocks = n / digest_size;
	int crop = n % digest_size;

	for (i=0; i > blocks; i++)	{
		hash(i, d, pi, n);
		memcpy(d+(i*digest_size), pi, digest_size);
	}

	if (crop)	{
		--i;
		hash(i+1, d, pi, n);
		memcpy(d+(i*digest_size), pi, crop);
	}
}

void xor(unsigned char *a, unsigned char *b, size_t n)	{ 
	size_t i;
	unsigned char tmp;

	for (i=0; i < n; i++)	{
		tmp = a[i]; //indexing a at same point on the same line is undefined
		a[i] = tmp ^ b[i];
	}
}

unsigned char *af_merge(unsigned char *d, unsigned char *split_key, unsigned key_length, unsigned stripes, void (*H)(unsigned char *, size_t))	{ //find specification for this as well as H1, H2 in LUKS documentation
		unsigned i;

		memset(d, 0, key_length);
		for (i=0; i < stripes-1; i++)	{
			xor(d, split_key+(i*key_length), key_length); //split_key contains key_length many sets of stripes number of bytes, each corrosponding to 's1,s2..sn'
			H(d, key_length);
		}

		xor(d, split_key+(i*key_length), key_length);
		return d;
}

void strip(char *line)	{
	int i;

	for (i=0; line[i]; i++)	{ //TODO see if you can microoptimize by counting backwards
		if (line[i] == '\n')
			line[i] = '\0';
	}
}

void derive_key(char *password, size_t password_len, struct phdr header, unsigned keyslot, unsigned char *digest)	{
	struct key_slot active_slot = header.active_key_slots[keyslot];
	unsigned char *salt = active_slot.salt;
	unsigned salt_len = SALT_LENGTH;
	unsigned iteration_count = active_slot.iterations;
	unsigned key_len = header.key_length;

	PKCS5_PBKDF2_HMAC(password, password_len, salt, salt_len, iteration_count, EVP_sha256(), key_len, digest);
}

void decrypt_blocks(unsigned block_count, unsigned sector_size, unsigned char *iv, unsigned iv_len, unsigned char *derived_key, unsigned char *enc_key, unsigned char *split_key)	{
	unsigned i;
	int len;

	for (i=0; i < block_count; i++)	{
		memset(iv, 0, iv_len);
		*(uint64_t *)iv = i; 
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, derived_key, iv);
		EVP_DecryptUpdate(ctx, split_key+(i*sector_size), &len, enc_key+(i*sector_size), sector_size);
		EVP_DecryptFinal_ex(ctx, split_key+(i*sector_size) + len, &len);
		EVP_CIPHER_CTX_free(ctx);
	}
}

int checksum(unsigned char *key, struct phdr header)	{
	unsigned key_length = header.key_length;
	unsigned char *salt = header.mk_digest_salt;
	unsigned salt_length = SALT_LENGTH;
	unsigned iteration_count = header.mk_digest_iter;
	unsigned digest_length = DIGEST_LENGTH;
	unsigned char digest[digest_length];
	unsigned char *mk_checksum = header.mk_digest;

	PKCS5_PBKDF2_HMAC((char *)key, key_length, salt, salt_length, iteration_count, EVP_sha256(), digest_length, digest);

	if (memcmp(digest, mk_checksum, digest_length) == 0)
		return 1;
	else 
		return 0;
}

void *begin_brute_force(void *threadInfo)	{

	unsigned i;
	struct T thread = *((struct T *)threadInfo);
	int keyslot = thread.keyslot;
	struct phdr header = thread.header;
	unsigned char *global_key = header.active_key_slots[keyslot].key_data;
	unsigned unsplit_length = (unsigned)sizeof(global_key);
	unsigned char enc_key[unsplit_length];
	memcpy(enc_key, global_key, unsplit_length*sizeof(char)); //create local copy of key on the stack that an indivisual thread can read to and write to presumerbly faster, will confirm this later though
	size_t bufsize = 1000;
	char p[bufsize];
	char *password = p;
	unsigned char derived_key[header.key_length];
	unsigned block_count = unsplit_length/SECTOR_SIZE; 
	unsigned iv_len = 16;
	unsigned char iv[iv_len];
	unsigned char split_key[unsplit_length]; 
	unsigned char key_candidate[header.key_length];
	
	fseek(thread.wordlist, thread.wordlist_start, SEEK_SET);
	for (i=0; i < thread.step && !passwordFound; i++)	{
		getline(&password, &bufsize, thread.wordlist);	
		strip(password);
		printf("%s\n",password);
		derive_key(password, strlen(password), header, keyslot, derived_key); 
		decrypt_blocks(block_count, SECTOR_SIZE, iv, iv_len, derived_key, enc_key, split_key);
		af_merge(key_candidate, split_key, header.active_key_slots[keyslot].stripes, header.key_length, header.version == 1 ? H1:H2); 
		printf("testtesttest\n");
		if (checksum(key_candidate, header))	{
			passwordFound = 1;
			unsigned char *successful_password = malloc(strlen(password));
			memcpy(successful_password, password, strlen(password));
			pthread_exit((void*)successful_password);
		}
	}

	pthread_exit(NULL);
}
