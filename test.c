#include <stdio.h>

int main()	{

	unsigned short data[1000];
	unsigned char data2[100];
	int i;

	FILE *fp;

	fp = fopen("/dev/sdb1", "rb");

	fseek(fp, 6, SEEK_SET);

	if (fp)	{
		for (i=0; i < 2; i++)	{
			fread(&data[i], sizeof(short), 1, fp);
		}

		fseek(fp, 72, SEEK_SET);

		for (i=0; i < 32; i++)	{
			fread(&data2[i], sizeof(char), 1, fp);
		}

		for (i=0; i < 2; i++)	{
			printf("%u\n", data[i]);
		}
		for (i=0; i < 32; i++)	{
			printf("%c", data2[i]);
		}
		printf("\n");
		
		fclose(fp);
	}
	else {
		printf("error\n");
	}

	return 0;
}
