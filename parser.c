#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#define LUKS_MAGIC 0x4c554b53babe
#define KEY_ACTIVE 0xAC71F3
#define MAGIC_LENGTH 6
#define NAME_LENGTH 32
#define KEY_SLOT_SIZE 48
#define SALT_LENGTH 32
#define DIGEST_LENGTH 20
#define TOTAL_KEY_SLOTS 8
#define FIRST_KEY_OFFSET 208

struct key_slot	{
	unsigned int iterations;
	unsigned char salt[SALT_LENGTH];
	unsigned int key_offset;
	unsigned int stripes;
};

struct phdr	{
	unsigned short version;
	char cipher_name[NAME_LENGTH];
	char cipher_mode[NAME_LENGTH];
	char hash_spec[NAME_LENGTH];
	unsigned int payload_offset;
	unsigned int key_bytes_length;
	unsigned char mk_digest[DIGEST_LENGTH];
	unsigned char mk_digest_salt[SALT_LENGTH];
	unsigned int mk_digest_iter;
	struct key_slot *active_key_slots[TOTAL_KEY_SLOTS];
};

void read_data(unsigned char *arr, int len, FILE *fp)	{
	int i;

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

struct phdr construct_header(FILE *fp)	{

	struct phdr header;

	fread(&header.version, sizeof(uint16_t), 1, fp);
	header.version = ntohs(header.version);

	read_data(header.cipher_name, NAME_LENGTH, fp);
	
	read_data(header.cipher_mode, NAME_LENGTH, fp);

	read_data(header.hash_spec, NAME_LENGTH, fp);

	fread(&header.payload_offset, sizeof(uint32_t), 1, fp);
	header.payload_offset = ntohl(header.payload_offset);

	read_data(header.mk_digest, DIGEST_LENGTH, fp);

	read_data(header.mk_digest_salt, SALT_LENGTH, fp);

	fread(&header.mk_digest_iter, sizeof(uint32_t), 1, fp);
	header.mk_digest_iter = ntohl(header.mk_digest_iter);
	
	return header;

}

void add_slot(struct phdr header, FILE *fp)	{
	
	static int i = 0;

	struct key_slot *slot = malloc(sizeof(struct key_slot));

	if (slot)	{
		fread(&(slot->iterations), sizeof(uint32_t), 1, fp);
		slot->iterations = ntohl(slot->iterations);

		read_data(slot->salt, SALT_LENGTH, fp);

		fread(&(slot->key_offset), sizeof(uint32_t), 1, fp);
		slot->key_offset = ntohl(slot->key_offset);

		fread(&(slot->stripes), sizeof(uint32_t), 1, fp);
		slot->iterations = ntohl(slot->stripes);

		header.active_key_slots[i] = slot;
		i++;
	}
	else	{
		printf("malloc error\n");
	}

}

void set_active_slots(struct phdr header, FILE *fp)	{
	fseek(fp, FIRST_KEY_OFFSET, SEEK_SET);
	int i;

	for (i=0; i < 8; i++)	{
		int active;
		
		fread(&active, sizeof(uint32_t), 1, fp);
		active = ntohl(active);

		if (active == KEY_ACTIVE)	{
			add_slot(header,fp); 
		}
		else {
			fseek(fp, KEY_SLOT_SIZE-4, SEEK_CUR);
		}
	}
}

void find_keys(struct phdr header, unsigned char **keys, FILE *fp)	{
	int i;

	for (i=0; header.active_key_slots[i]; i++)	{
		fseek(fp, (size_t)header.active_key_slots[i]->key_offset, SEEK_SET);		
		read_data(keys[i], header.key_bytes_length, fp); 
	}
}

int main(int argc, char *argv[])	{
	char *drive = *++argv;
	printf("%s\n", drive);
	FILE *fp;
	struct phdr header;

	fp = fopen(drive, "rb");

	if (fp && is_luks_volume(fp))	{
		header = construct_header(fp); 
	}
	else	{
		printf("not a valid luks volume\n");
		fclose(fp);
		return 1;
	}

	unsigned char *keys[TOTAL_KEY_SLOTS];

	set_active_slots(header, fp);
	find_keys(header, keys, fp);

	fclose(fp);
	return 0;
}
