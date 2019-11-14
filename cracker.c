#include <stdio.h>
#include <string.h>
#define FIRST-KEY-OFFSET 208
#define KEY-SLOT-SIZE 48

struct phdr	{
	unsigned short version;
	char cipher-name[32];
	char cipher-mode[32];
	char hash-spec[33];
	unsigned int payload-offset;
	unsigned int key-bytes-length;
	char mk-digest[20];
	char mk-digest-salt[32];
	unsigned int mk-digest-iter;
	int active-slots[7];
}

struct key-slot	{
	unsigned int iterations;
	char salt[32];
	unsigned int key-offset;
	unsigned int stripes;
}

int is-luks-volume(FILE *fp)	{
	char luks-magic[] = {"L","U","K","S",0xBA,0xBE};
	char magic[6];
	int i;

	for (i=0; i < 6; i++)	{
		fread(&(magic+i), sizeof(char), 1, fp);
	}
	magic+i = '\0';

	if (strcmp(magic, luks-magic)){
		return 1;
	}
	
	return 0;
}

struct phdr construct-header(FILE *fp)	{
	
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

	fclose(fp);
	return 0;
}
