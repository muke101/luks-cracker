#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define FIRST_KEY_OFFSET 208
#define KEY_SLOT_SIZE 48
#define SALT_LENGTH 32
#define DIGEST_LENGTH 20
#define TOTAL_KEY_SLOTS 8

struct key_slot	{
	unsigned int iterations[4];
	unsigned char salt[SALT_LENGTH];
	unsigned int key_offset[4];
	unsigned int stripes[4];
}

struct phdr	{
	unsigned short version[2];
	char cipher_name[33];
	char cipher_mode[33];
	char hash_spec[33];
	unsigned int payload_offset[4];
	unsigned int key_bytes_length[4];
	unsigned char mk_digest[DIGEST_LENGTH];
	unsigned char mk_digest_salt[SALT_LENGTH];
	unsigned int mk_digest_iter[4];
	struct key_slot *active_key_slots[TOTAL_KEY_SLOTS];
}

void read_data(void *arr, size_t size, int len, FILE *fp)	{
	int i;

	for (i=0, i < len; i++)	{
		fread(&arr[i], size, 1, fp);
	}
}

int is_luks_volume(FILE *fp)	{
	unsigned char luks_magic[] = {"L","U","K","S",0xBA,0xBE};
	unsigned char magic[6];
	int i;

	read_data(magic, sizeof(char), 6, fp);

	if (memcmp(magic, luks_magic, 6) == 0){
		return 1;
	}
	
	return 0;
}

struct phdr construct_header(FILE *fp)	{
	int i;

	struct phdr header;

	read_data(header.version, sizeof(short), 2, fp);

	read_data(header.cipher_name, sizeof(char), 32, fp);
	*(header.cipher_name+1) = '\0';
	
	read_data(header.cipher_mode, sizeof(char), 32, fp);
	*(header.cipher_mode+1) = '\0';

	read_data(header.hash_spec, sizeof(char), 32, fp);
	*(header.hash_spec+1) = '\0';

	read_data(header.payload_offset, sizeof(int), 4, fp);

	read_data(header.mk_digest, sizeof(char), DIGEST_LENGTH, fp);

	read_data(header.mk_digest_salt, sizeof(char), SALT_LENGTH, fp);

	read_data(header.mk_digest_iter, sizeof(int), 4, fp);
	
	return header;

}

void add_slot(FILE *fp, struct phdr header, struct key-slot slot)	{

	//todo: sort out struct passing
	static int i = 0;

	read_data(slot.iterations, sizeof(int), 4, fp);

	read_data(slot.salt, sizeof(char), SALT_LENGTH, fp);

	read_data(slot.key_offset, sizeof(int), 4, fp);

	read_data(slot.stripes, sizeof(int), 4, fp);

	header.active_key_slots[i] = &slot;
	i++;

}

void set_active_slots(struct phdr header, FILE *fp)	{
	fseek(fp, FIRST_KEY_OFFSET, SEEK_SET);
	int i;

	for (i=0; i < 8; i++)	{
		int active[4];
		read_data(active, sizeof(int), 4, fp);

		if (is_active(active))	{
			add_slot(fp); //todo: implement
		}
		else {
			fseek(fp, KEY_SLOT_SIZE-4, SEEK_CUR);
		}
	}
}

void find_keys(struct phdr header, unsigned char *keys, FILE *fp)	{
	int i, key_length;

	switch header.cipher_name	{

	}
	
	for (i=0; header.active_key_slots[i] != NULL; i++)	{
		fseek(fp, header.active_key_slots[i]->key_offset, SEEK_SET);		
		read_data(keys[i], sizeof(char), key_length, fp);
	}

}

int main(int argc, char *argv[])	{
	char *drive = argv+1;
	FILE *fp;

	fp = fopen(drive, "rb");

	if (fp != NULL && is_luks_volume(fp))	{
		struct phdr header = construct_header(fp); 
	}
	else	{
		printf("not a valid luks volume\n");
		fclose(fp);
		return 1;
	}

	unsigned char *keys[TOTAL_KEY_SLOTS];

	set_active_slots(header, fp);
	find_keys(header, keys);

	fclose(fp);
	return 0;
}
