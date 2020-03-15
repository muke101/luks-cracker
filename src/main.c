#include "parser.h"
#include "cracker.h"
#include <ctype.h>

int main(int argc, char **argv)	{
	struct phdr header;
	int i, j, wordlist_found = 0, device_found = 0, threads_found = 0;
	unsigned number_of_threads;
	char *device, *wordlist, *threads;
	FILE *header_file, *wordlist_file;
	
	if (argc == 1)	{
		printf("Usage: lukscrack [-j number of threads] [-w wordlist] [-d LUKS device]\n");
		return 0;
	}

	for (i=0; i < argc && !threads_found; i++)	{
		if (strncmp(argv[i], "-j", 2) == 0)	{
			threads = argv[++i];
			threads_found = 1;
		}
		else if (strncmp(argv[i], "--threads", 9) == 0)	{
			threads = argv[++i];
			threads_found = 1;
		}
	}

	for (i=0; i < argc && !wordlist_found; i++)	{
		if (strncmp(argv[i], "-w", 2) == 0)	{
			wordlist = argv[++i];
			wordlist_found = 1;
		}

 		else if (strncmp(argv[i], "--wordlist", 10) == 0)	{	
			wordlist = argv[++i];
			wordlist_found = 1;
		}
	}

	if (!wordlist_found)	{
		printf("please supply a wordlist using -w <wordlist>\n");
		return 1;
	}

	for (i=0; i < argc && !device_found; i++)	{
		if (strncmp(argv[i], "-d", 2) == 0)	{
			device = argv[++i];
			device_found = 1;
		}
		else if (strncmp(argv[i], "--device", 8) == 0)	{
			device = argv[++i];
			device_found = 1;
		}
	}

	if (!threads_found)	{
		printf("please specify number of threads with -j <number of threads>\n");
		return 1;
	}

	if (!device_found)	{
		printf("please supply a LUKS encrypted device or file containing a LUKS header with -d <device>\n");
		return 1;
	}

	for (i=0; isdigit(*(threads+i)); i++);
	if (threads[i] != '\0')	{
		printf("invalid threads number\n");
		return 1;
	}

	number_of_threads = atoi(threads);

	header_file = fopen(device, "r");

	if (header_file && is_luks_header(header_file))
		header = parse_header(header_file);
	else if (header_file)	{
		fseek(header_file, 512, SEEK_SET); //allow raw device nodes where LUKS header is first petition	
		if (is_luks_header(header_file))
			header = parse_header(header_file);
		else	{
			printf("invalid LUKS header\n");
			return 1;
		}
	}
	else	{
		printf("%s: no such file\n", device);
		return 1;
	}

	wordlist_file = fopen(wordlist, "r");

	if (!wordlist_file)	{
		printf("%s: no such file\n", wordlist); //TODO cover case where it's a permissions error
		return 1;
	}

	crack(header, wordlist_file, number_of_threads);

	fclose(header_file);
	fclose(wordlist_file);

	return 0;
}
