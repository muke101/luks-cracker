#include "parser.h"
#include "cracker.h"
#include <ctype.h>

int main(int argc, char **argv)	{
	struct phdr header;
	int i, j, wordlistFound = 0, deviceFound = 0, threadsFound = 0;
	unsigned threadsNumber;
	char *device, *wordlist, *threads;
	FILE *fp, *wordlistFile;
	
	if (argc == 1)	{
		printf("Usage: lukscrack [-j number of threads] [-w wordlist] [-d LUKS device]\n");
		return 0;
	}

	for (i=0; i < argc && !threadsFound; i++)	{
		if (strncmp(argv[i], "-j", 2) == 0)	{
			threads = argv[++i];
			threadsFound = 1;
		}
		else if (strncmp(argv[i], "--threads", 9) == 0)	{
			threads = argv[++i];
			threadsFound = 1;
		}
	}

	for (i=0; i < argc && !wordlistFound; i++)	{
		if (strncmp(argv[i], "-w", 2) == 0)	{
			wordlist = argv[++i];
			wordlistFound = 1;
		}

 		else if (strncmp(argv[i], "--wordlist", 10) == 0)	{	
			wordlist = argv[++i];
			wordlistFound = 1;
		}
	}

	if (!wordlistFound)	{
		printf("please supply a wordlist using -w <wordlist>\n");
		return 1;
	}

	for (i=0; i < argc && !deviceFound; i++)	{
		if (strncmp(argv[i], "-d", 2) == 0)	{
			device = argv[++i];
			deviceFound = 1;
		}
		else if (strncmp(argv[i], "--device", 8) == 0)	{
			device = argv[++i];
			deviceFound = 1;
		}
	}

	if (!threadsFound)	{
		printf("please specify number of threads with -j <number of threads>\n");
		return 1;
	}

	if (!deviceFound)	{
		printf("please supply a LUKS encrypted device or file containing a LUKS header with -d <device>\n");
		return 1;
	}

	for (i=0; isdigit(*(threads+i)); i++);
	if (threads[i] != '\0')	{
		printf("invalid threads number\n");
		return 1;
	}

	threadsNumber = atoi(threads);

	fp = fopen(device, "r");

	if (fp && is_luks_header(fp))
		header = parse_header(fp);
	else if (fp)	{
		fseek(fp, 512, SEEK_SET); //allow raw device nodes where LUKS header is first petition	
		if (is_luks_header(fp))
			header = parse_header(fp);
		else	{
			printf("invalid LUKS header\n");
			return 1;
		}
	}
	else	{
		printf("%s: no such file\n", device);
		return 1;
	}

	wordlistFile = fopen(wordlist, "r");

	if (!wordlistFile)	{
		printf("%s: no such file\n", wordlist); //TODO cover case where it's a permissions error
		return 1;
	}

	crack(header, wordlistFile, threadsNumber);

	return 0;
}
