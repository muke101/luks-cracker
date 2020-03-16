#ifndef PARSER_H_
#define PARSER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
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
#define SECTOR_SIZE 512 
#define SHA256_DIGEST_SIZE 256

struct key_slot {
    unsigned int iterations;
    unsigned char salt[SALT_LENGTH];
    unsigned int key_offset;
    unsigned int stripes;
	unsigned char *key_data;
};

struct phdr {
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
    int active_slot_count;
};

int is_luks_header(FILE *fp);

struct phdr parse_header(FILE *fp);

#endif
