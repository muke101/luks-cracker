#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <openssl/sha.h>
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

void af_merge(unsigned char *split_key, unsigned length, unsigned *(H)(unsigned))	{ //find specification for this as well as H1, H2 in LUKS documentation
		int i, d0, d1;

		d0 = 0;
		for (i=0; i < length-1; i++)	{
			d1 = H(d0 ^ split_key[i]);
			d0 = d1;
		}

		return d1 ^ split_key[++i];	
}

unsigned H1(unsigned d)	{
		
}

int find_keys(struct phdr header, unsigned char keys[8][64*4000], FILE *fp)	{ //FIXME: array length
	int i;

	for (i=0; header.active_key_slots[i]; i++)	{
		unsigned offset = header.active_key_slots[i]->key_offset, stripes = header.active_key_slots[i]->stripes, length = header.key_length;
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

	int i;
	unsigned j;
	for (i=0; i < number_of_keys; i++)	{
		for (j=0; j < header.key_length*4000; j++)	{
			//printf("%c", keys[i][j]);
		}
		printf("\n");
	}

	fclose(fp);
	return 0;
}
