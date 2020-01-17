#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#define LUKS_MAGIC 0x4c554b53babe
#define KEY_ACTIVE 0xAC71F3
#define MAGIC_LENGTH 6
#define NAME_LENGTH 32
#define KEY_SLOT_SIZE 48
#define SALT_LENGTH 32
#define DIGEST_LENGTH 20
#define TOTAL_KEY_SLOTS 8
#define FIRST_KEY_OFFSET 208
#define SECTOR_SIZE 512
#define SHA256_DIGEST_SIZE 256

struct key_slot	{
	unsigned int iterations;
	unsigned char salt[SALT_LENGTH];
	unsigned int key_offset;
	unsigned int stripes;
};

struct phdr	{
	unsigned short version;
	unsigned char cipher_name[NAME_LENGTH];
	unsigned char cipher_mode[NAME_LENGTH];
	unsigned char hash_spec[NAME_LENGTH];
	unsigned int payload_offset;
	unsigned int key_length;
	unsigned char mk_digest[DIGEST_LENGTH];
	unsigned char mk_digest_salt[SALT_LENGTH];
	unsigned int mk_digest_iter;
	struct key_slot *active_key_slots[TOTAL_KEY_SLOTS];
};

void read_data(unsigned char *arr, unsigned int len, FILE *fp)	{
	unsigned i;

	for (i=0; i < len; i++)	{
		fread(&arr[i], sizeof(char), 1, fp);
	}
}

int is_luks_volume(FILE *fp)	{
	unsigned char magic[MAGIC_LENGTH];
	unsigned char luks_magic[] = {'L','U','K','S',0xBA,0xBE};

	read_data(magic, MAGIC_LENGTH, fp);

	if (memcmp(magic, luks_magic, MAGIC_LENGTH) == 0){
		return 1;
	}
	
	return 0;
}

void construct_header(struct phdr *header, FILE *fp)	{

	fread(&header->version, sizeof(uint16_t), 1, fp);
	header->version = ntohs(header->version);

	read_data(header->cipher_name, NAME_LENGTH, fp);
	
	read_data(header->cipher_mode, NAME_LENGTH, fp);

	read_data(header->hash_spec, NAME_LENGTH, fp);

	fread(&header->payload_offset, sizeof(uint32_t), 1, fp);
	header->payload_offset = ntohl(header->payload_offset);

	fread(&header->key_length, sizeof(uint32_t), 1, fp);
	header->key_length = ntohl(header->key_length);

	read_data(header->mk_digest, DIGEST_LENGTH, fp);

	read_data(header->mk_digest_salt, SALT_LENGTH, fp);

	fread(&header->mk_digest_iter, sizeof(uint32_t), 1, fp);
	header->mk_digest_iter = ntohl(header->mk_digest_iter);

}

void add_slot(struct phdr *header, FILE *fp)	{
	
	static int i = 0;

	struct key_slot *slot = malloc(sizeof(struct key_slot));

	if (slot)	{
		fread(&(slot->iterations), sizeof(uint32_t), 1, fp);
		slot->iterations = ntohl(slot->iterations);

		read_data(slot->salt, SALT_LENGTH, fp);

		fread(&(slot->key_offset), sizeof(uint32_t), 1, fp);
		slot->key_offset = ntohl(slot->key_offset);

		fread(&(slot->stripes), sizeof(uint32_t), 1, fp);
		slot->stripes = ntohl(slot->stripes);

		header->active_key_slots[i] = slot;
		i++;
	}
	else	{
		printf("malloc error\n");
	}

}

void set_active_slots(struct phdr *header, FILE *fp)	{
	fseek(fp, FIRST_KEY_OFFSET, SEEK_SET);
	int i;
	unsigned active;

	for (i=0; i < TOTAL_KEY_SLOTS; i++)	{

		fread(&active, sizeof(uint32_t), 1, fp);
		active = ntohl(active);

		if (active == KEY_ACTIVE)	{ //turns out I don't understand how file pointers work but I *think* this is fine??
			add_slot(header,fp); 
		}
		else { //calling add_slot will parse the rest of the key slot and leave fp at the beginning of the next slot
			fseek(fp, KEY_SLOT_SIZE-4, SEEK_CUR);
		}
	}
}

void hash(unsigned i, unsigned char *di, unsigned char *pi, size_t len)	{
	i = htonl(i);
	unsigned i_arr[sizeof(uint32_t)];
	memcpy(i_arr, &i, sizeof(uint32_t));
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, i_arr, sizeof(uint32_t));
	SHA256_Update(&ctx, di, len);
	SHA256_Final(pi, &ctx);
}                                                                        

void H1(unsigned char *d, size_t n)	{
	unsigned i;
	size_t digest_size = SHA256_DIGEST_SIZE/8; //not making this portable for non-default hash functions for now
	unsigned char di[digest_size];
	unsigned char pi[digest_size];
	int blocks = n / digest_size;
	int crop = n % digest_size;
	
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
	unsigned i;
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

void xor(unsigned char *a, unsigned char *b, unsigned char *dst, size_t n)	{ //for some reason cryptsetup does it b^a?
	size_t i;

	for (i=0; i < n; i++)	{
		dst[i] = a[i] ^ b[i];
	}
}

unsigned char *af_merge(unsigned char *split_key, size_t key_length, unsigned stripes, void (*H)(unsigned char *, size_t))	{ //find specification for this as well as H1, H2 in LUKS documentation
		int i;
		unsigned char *d = calloc(key_length, sizeof(char));

		for (i=0; i < stripes-1; i++)	{
			xor(split_key+(i*key_length), d, d, key_length); //split_key contains key_length many sets of stripes number of bytes, each corrosponding to 's1,s2..sn'
			H(d, key_length);
		}

		xor(split_key+(i*key_length), d, d, key_length);
		return d;
}

void test_key(unsigned char *enc_key, const char *pass, struct phdr header)	{
	int split_length = header.key_length*header.active_key_slots[0]->stripes;
	unsigned char split_key[split_length];
	const unsigned char *key; 
	unsigned char *iv = malloc(header.key_length/2);
	unsigned char digest[header.key_length];
	int len;

	PKCS5_PBKDF2_HMAC(pass, strlen(pass), header.active_key_slots[0]->salt, SALT_LENGTH, header.active_key_slots[0]->iterations, EVP_sha256(), header.key_length, digest); 

	memset(iv, 0, header.key_length/2);
	*(uint64_t *)iv = header.active_key_slots[0]->key_offset;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, digest, iv);
	EVP_DecryptUpdate(ctx, split_key, &len, enc_key, split_length);
	EVP_DecryptFinal_ex(ctx, split_key + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	key = af_merge(enc_key, (size_t)header.key_length, header.active_key_slots[0]->stripes, header.version == 1 ? H1:H2); 

	PKCS5_PBKDF2_HMAC(key, header.key_length, header.mk_digest_salt, SALT_LENGTH, header.mk_digest_iter, EVP_sha256(), 20, digest);

	
	if (memcmp(digest, header.mk_digest, 20) == 0)	{
		printf("match!");
	}
}

int find_keys(struct phdr header, unsigned char keys[8][64*4000], FILE *fp)	{ //FIXME: array length
	int i;

	for (i=0; header.active_key_slots[i]; i++)	{
		unsigned offset = header.active_key_slots[i]->key_offset;
		unsigned stripes = header.active_key_slots[i]->stripes;
		unsigned length = header.key_length;
		fseek(fp, (size_t)offset*SECTOR_SIZE, SEEK_SET);	
		read_data(keys[i], length*stripes, fp); 
	}

	return i;
}

int main(int argc, char *argv[])	{
	char *drive = *++argv;
	FILE *fp;
	struct phdr header;
	memset(header.active_key_slots, 0, TOTAL_KEY_SLOTS*sizeof(struct key_slot *)); 

	fp = fopen(drive, "rb");

	if (fp && is_luks_volume(fp))	{
		construct_header(&header, fp); 
	}
	else	{
		printf("not a valid luks volume\n");
		return 1;
	}

	unsigned char keys[TOTAL_KEY_SLOTS][64*4000];

	set_active_slots(&header, fp);
	int number_of_keys = find_keys(header, keys, fp);

	printf("%s\n",header.cipher_mode);

	int i;
	unsigned char *key;
	for (i=0; i < number_of_keys; i++)	{
		test_key(keys[i], "password", header);
	}

	fclose(fp);
	return 0;
}
