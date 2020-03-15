#include "parser.h"
#include "cracker.h"


unsigned long count_lines(FILE *fp)	{
	unsigned long i;
	char c;

	for (i=0; fread(&c, sizeof(char), 1, fp);)
		if (c == '\n')
			i++;

	return i;
}

char *crack(struct phdr header, FILE *wordlist, unsigned thread_number, unsigned number_of_keyslots)	{
	int i, j;
	unsigned long password_number, passwords_per_thread, remainder;
	char password[thread_number][1000]; //here's hoping someone doesn't use a password longer than 1000 characters I guess
	password_number = count_lines(wordlist);	
	passwords_per_thread = password_number/thread_number; //integer devision, will just mean the last thread takes on a couple more than the others if there are remainders
	remainder = password_number % thread_number;

	struct T threads[thread_number];

	for (i=0; i < number_of_keyslots; i++)	{

		for (j=0; j < thread_number; j++)	{
			threads[j].wordlist_start = j*passwords_per_thread;
			threads[j].header = header;
			threads[j].wordlist = wordlist;
			threads[j].step = passwords_per_thread;
			threads[j].keyslot = i;
		}

		for (j=0; j < thread_number; j++)	{
			pthread_create(&(threads[j].id), NULL, begin_brute_force, &(threads[j])); 
		}

		for (j=0; j < thread_number; j++)	{
			pthread_join(threads[j].id, password[j]); 
		}

		for (j=0; j < thread_number; j++)	{
			if (password[j][0] != 0xff)	{ //hack based on the fact we want to store chars and pthread will write the highest memory address as a constant to signify a thread was cancelled, but it works
				return password[j];
			}
		}

	}


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

unsigned char *af_merge(unsigned char *split_key, unsigned key_length, unsigned stripes, void (*H)(unsigned char *, size_t))	{ //find specification for this as well as H1, H2 in LUKS documentation
		unsigned i;
		unsigned char *d = calloc((size_t)key_length, sizeof(char));

		for (i=0; i < stripes-1; i++)	{
			xor(d, split_key+(i*key_length), key_length); //split_key contains key_length many sets of stripes number of bytes, each corrosponding to 's1,s2..sn'
			H(d, key_length);
		}

		xor(d, split_key+(i*key_length), key_length);
		return d;
}

void strip(char *line)	{
	int i;

	for (i=0; *line[i]; i++)	{ //TODO see if you can microoptimize by counting backwards
		if (*line[i] == '\n')
			*line[i] = '\0';
	}
}

void 

void *begin_brute_force(void *thread)	{

	int i;
	int keyslot = thread->keyslot;
	struct phdr header = thread->header;
	unsigned char *global_key = header.active_key_slots[keyslot].key_data;
	unsigned char key[sizeof(global_key)];
	memcpy(key, global_key, sizeof(global_key)*sizeof(char)); //create local copy of key on the stack that an indivisual thread can read to and write to presumerbly faster, will confirm this later though
	fseek(thread->wordlist, thread->wordlist_start, SEEK_SET);
	char password[1000];
	size_t password_len;
	
	for (i=0; i < thread->step; i++)	{
		getline(password, &password_len, thread->wordlist);	
		strip(password);


	}


	
}

void test_key(unsigned char *enc_key, const char *pass, struct phdr header)	{
	int split_length = header.key_length*header.active_key_slots[0].stripes;
	size_t iv_length = 16;
	unsigned char split_key[split_length];
	unsigned char *key; 
	unsigned char *iv = malloc(iv_length);
	unsigned char psk_digest[header.key_length];
	unsigned char key_digest[DIGEST_LENGTH];
	int len;

	PKCS5_PBKDF2_HMAC(pass, strlen(pass), header.active_key_slots[0].salt, SALT_LENGTH, header.active_key_slots[0].iterations, EVP_sha256(), header.key_length, psk_digest); 

	for (int i=0; i < split_length/SECTOR_SIZE; ++i)	{ //TODO formalize sector shifting to form data chunks
		memset(iv, 0, iv_length);
		*(uint64_t *)iv = i; //dm-crypt documentation has iv setting rules
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, psk_digest, iv);
		EVP_DecryptUpdate(ctx, split_key+(i*SECTOR_SIZE), &len, enc_key+(i*SECTOR_SIZE), SECTOR_SIZE);
		EVP_DecryptFinal_ex(ctx, split_key+(i*SECTOR_SIZE) + len, &len);
		EVP_CIPHER_CTX_free(ctx);
	}

	key = af_merge(split_key, header.key_length, header.active_key_slots[0].stripes, header.version == 1 ? H1:H2); 

	PKCS5_PBKDF2_HMAC((char *)key, header.key_length, header.mk_digest_salt, SALT_LENGTH, header.mk_digest_iter, EVP_sha256(), DIGEST_LENGTH, key_digest);

	for (len=0; len < DIGEST_LENGTH; len++)	{ 
		printf("%c", key_digest[len]);
	}
	printf("\n");

	for (len=0; len < DIGEST_LENGTH; len++)	{
		printf("%c", header.mk_digest[len]); 
	}
	printf("\n");

	
	if (memcmp(key_digest, header.mk_digest, DIGEST_LENGTH) == 0)	{
		printf("match!\n");
	}
}

