#include <stdio.h>
#include <arpa/inet.h>
#define ACTIVE 0xAC71F3

int main()	{

	unsigned int data[100];
	unsigned char data2[100];
	unsigned int data3[100];
	int i;

	FILE *fp;

	fp = fopen("/dev/sdd1", "rb");

	fseek(fp, 208, SEEK_SET);

	if (fp)	{

		fread(&data[0], sizeof(int), 1, fp);
		fread(&data[1], sizeof(int), 1, fp);

		if (ntohl(data[0]) == ACTIVE)	{
			printf("is active\n");
		}
		
		fclose(fp);
	}

	//if (fp)	{
	//	for (i=0; i < 2; i++)	{
	//		fread(&data[i], sizeof(short), 1, fp);
	//		data[i] = ntohs(data[i]);
	//	}

	//	fseek(fp, 72, SEEK_SET);

	//	for (i=0; i < 32; i++)	{
	//		fread(&data2[i], sizeof(char), 1, fp);
	//	}

	//	fseek(fp, 108, SEEK_SET);

	//	for (i=0; i < 4; i++)	{
	//		fread(&data3[i], sizeof(int), 1, fp);
	//		data3[i] = ntohs(data[i]);
	//	}

	//	printf("version:\n");
	//	for (i=0; i < 2; i++)	{
	//		printf("%u\n", data[i]);
	//	}
	//	printf("hash spec:\n");
	//	for (i=0; i < 32; i++)	{
	//		printf("%c", data2[i]);
	//	}
	//	printf("\n");
	//	printf("key bytes (length):\n");
	//	for(i=0; i < 4; i++)	{
	//		printf("%u\n", data3[i]);
	//	}
	//	
	//	fclose(fp);
	//}
	//else {
//		printf("error\n");
//	}

	return 0;
}
