#include "parser.h"
#include "cracker.h"

void crack(struct phdr header, FILE *wordlist, int threads)	{

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

