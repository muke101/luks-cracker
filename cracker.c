#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define FIRST-KEY-OFFSET 208
#define KEY-SLOT-SIZE 48
#define SALT-LENGTH 32
#define DIGEST-LENGTH 20
#define TOTAL-KEY-SLOTS 8

struct key-slot	{
	unsigned int iterations[3];
	unsigned char salt[SALT-LENGTH-1];
	unsigned int key-offset[3];
	unsigned int stripes[3];
}
struct phdr	{
	unsigned short version[1];
	char cipher-name[32];
	char cipher-mode[32];
	char hash-spec[32];
	unsigned int payload-offset[3];
	unsigned int key-bytes-length[3];
	unsigned char mk-digest[DIGEST-LENGTH-1];
	unsigned char mk-digest-salt[SALT-LENGTH-1];
	unsigned int mk-digest-iter[3];
	struct key-slot active-key-slots[TOTAL-KEY-SLOTS-1];
}

int is-luks-volume(FILE *fp)	{
	unsigned char luks-magic[] = {"L","U","K","S",0xBA,0xBE};
	unsigned char magic[5];
	int i;

	for (i=0; i < 6; i++)	{
		fread(&(magic+i), sizeof(char), 1, fp);
	}

	if (memcmp(magic, luks-magic, 6) == 0){
		return 1;
	}
	
	return 0;
}

struct phdr construct-header(FILE *fp)	{
	int i;

	struct phdr header;

	for (i=0; i < 2; i++)	{
		fread(&(header.version+i), sizeof(short), 1, fp);
	}
	for (i=0; i < 32; i++)	{
		fread(&(header.cipher-name+i), sizeof(char), 1, fp);
	}
	*(header.cipher-name+i) = '\0';
	for (i=0; i < 32; i++)	{
		fread(&(header.cipher-mode+i), sizeof(char), 1, fp);
	}
	*(header.cipher-mode+i) = '\0';
	for (i=0; i < 32; i++)	{
		fread(&(header.hash-spec+i), sizeof(char), 1, fp);
	}
	*(header.hash-spec+i) = '\0';
	for (i=0; i < 4; i++)	{
		fread(&(header.payload-offset+i), sizeof(int), 1, fp);
	}
	for (i=0; i < DIGEST-LENGTH; i++)	{
		fread(&(header.mk-digest+i), sizeof(char), 1, fp);
	}
	for (i=0; i < SALT-LENGTH; i++)	{
		fread(&(header.mk-digest-salt+i), sizeof(char), 1, fp);
	}
	for (i=0; i < 4; i++)	{
		fread(&(header.mk-digest-iter+i), sizeof(int), 1, fp);
	}
	
	return header;

}

void add-slot(FILE *fp, struct phdr header)	{
	struct key-slot slot;

	static int i = 0;

	for (i=0; i < 4; i++)	{
		fread(&(slot.iterations+i), sizeof(int), 1, fp);
	}
	for (i=0; i < SALT-LENGTH; i++)	{
		fread(&(slot.salt+i), sizeof(char), 1, fp);
	}
	for (i=0; i < 4; i++)	{
		fread(&(slot.key-offset+i), sizeof(int), 1, fp);
	}
	for (i=0; i < 4; i++)	{
		fread(&(slot.stripes+i), sizeof(int), 1, fp);
	}

	header.active-key-slots[i] = slot;
	i++;

}

void set-active-slots(struct phdr header, FILE *fp)	{
	fseek(fp, FIRST-KEY-OFFSET, SEEK_SET);

	int i;

	for (i=0; i < 8; i++)	{
		int active[3];
		for (i=0; i < 4; i++)	{
			fread(&(active+i), sizeof(int), 1, fp);
		}
		if (is-active(active))	{
			add-slot(fp);
		}
		else {
			fseek(fp, KEY-SLOT-SIZE-4, SEEK_CUR);
		}
	}
}

void find-keys(struct phdr header, unsigned char *keys)	{
	int i;

	for (i=0; header.active-key-slots[i] != NULL; i++)	{
		
	}

}

int main(int argc, char *argv[])	{
	char *drive = argv+1;
	FILE *fp;

	fp = fopen(drive, "rb");

	if (fp != NULL && is-luks-volume(fp))	{
		struct phdr header = construct-header(fp); 
	}
	else	{
		printf("not a valid luks volume\n");
		fclose(fp);
		return 1;
	}

	unsigned char *keys[TOTAL-KEY-SLOTS-1];

	set-active-slots(header, fp);
	find-keys(header, keys);

	fclose(fp);
	return 0;
}
