#include "parser.h"

void read_data(unsigned char *arr, unsigned len, FILE *fp)	{
	unsigned i;

	for (i=0; i < len; i++)	{
		fread(&arr[i], sizeof(char), 1, fp);
	}
}

int is_luks_header(FILE *fp)	{
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
	header->version = be16toh(header->version);

	read_data(header->cipher_name, NAME_LENGTH, fp);
	
	read_data(header->cipher_mode, NAME_LENGTH, fp);

	read_data(header->hash_spec, NAME_LENGTH, fp);

	fread(&header->payload_offset, sizeof(uint32_t), 1, fp);
	header->payload_offset = be32toh(header->payload_offset);

	fread(&header->key_length, sizeof(uint32_t), 1, fp);
	header->key_length = be32toh(header->key_length);

	read_data(header->mk_digest, DIGEST_LENGTH, fp);

	read_data(header->mk_digest_salt, SALT_LENGTH, fp);

	fread(&header->mk_digest_iter, sizeof(uint32_t), 1, fp);
	header->mk_digest_iter = be32toh(header->mk_digest_iter);

}

void add_slot(struct phdr *header, FILE *fp)	{

	int i = header->active_slot_count-1;
	struct key_slot *slot = malloc(sizeof(struct key_slot));

	fread(&(slot->iterations), sizeof(uint32_t), 1, fp);
	slot->iterations = be32toh(slot->iterations);

	read_data(slot->salt, SALT_LENGTH, fp);

	fread(&(slot->key_offset), sizeof(uint32_t), 1, fp);
	slot->key_offset = be32toh(slot->key_offset);

	fread(&(slot->stripes), sizeof(uint32_t), 1, fp);
	slot->stripes = be32toh(slot->stripes);

	header->active_key_slots[i] = slot;
}


void set_active_slots(struct phdr *header, FILE *fp)	{
	fseek(fp, FIRST_KEY_OFFSET, SEEK_SET);
	unsigned i, active;
	header->active_slot_count=0;

	for (i=0; i < TOTAL_KEY_SLOTS; i++)	{
		fread(&active, sizeof(uint32_t), 1, fp);
		active = be32toh(active);

		if (active == KEY_ACTIVE)	{ 
			header->active_slot_count+=1;
			add_slot(header,fp); 
		}
		else { //calling add_slot will parse the rest of the key slot and leave fp at the beginning of the next slot
			fseek(fp, KEY_SLOT_SIZE-4, SEEK_CUR);
		}
	}
}

void find_keys(struct phdr *header, FILE *fp)	{ 
	int i;

	for (i=0; i < header->active_slot_count; i++)	{
		unsigned offset = header->active_key_slots[i]->key_offset;
		unsigned stripes = header->active_key_slots[i]->stripes;
		unsigned length = header->key_length;
		unsigned char *key = malloc(length*stripes*sizeof(char));
		fseek(fp, (size_t)offset*SECTOR_SIZE, SEEK_SET);	
		read_data(key, length*stripes, fp); 
		header->active_key_slots[i]->key_data = key;
	}
}

struct phdr parse_header(FILE *fp)	{
	struct phdr header;

	construct_header(&header, fp); 

	set_active_slots(&header, fp);

	find_keys(&header, fp); 

	return header;
}
