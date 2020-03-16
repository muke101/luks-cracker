#include "parser.h"
#include "cracker.h"
#include <ctype.h>

int main(int argc, char **argv)	{
	struct phdr header;
	int i, j, wordlist_found = 0, device_found = 0, threads_found = 0, number_found = 0;
	unsigned number_of_threads, number_of_slots;
	char *device, *wordlist, *threads, *number;
	FILE *header_file, *wordlist_file;
	
	if (argc == 1)	{
		printf("Usage: lukscrack [-j number of threads] [-n number of key slots to attempt to crack] [-w wordlist] [-d LUKS device]\n");
		return 0;
	}

	for (i=0; i < argc && !threads_found; i++)	{ //TODO handle missing arguments but present flags
		if (strncmp(argv[i], "-j", 2) == 0)	{
			threads = argv[++i];
			threads_found = 1;
		}
		else if (strncmp(argv[i], "--threads", 9) == 0)	{
			threads = argv[++i];
			threads_found = 1;
		}
	}

	for (i=0; i < argc && !number_found; i++)	{
		if (strncmp(argv[i], "-n", 2) == 0)	{
			number = argv[++i];
			number_found = 1;
		}
		else if (strncmp(argv[i], "--number", 8) == 0)	{
			number = argv[++i];
			number_found = 1;
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

	if (!number_found)	{
		printf("please specify number of key slots to attempt with -n <number of key slots>\n");
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

	for (i=0; isdigit(*(number+i)); i++);
	if (number[i] != '\0')	{
		printf("invalid key slot number\n");
		return 1;
	}
	number_of_slots = atoi(number); //TODO see if non-consecuitive key slots are allowed and handle if so

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

	if (number_of_slots > (unsigned)header.active_slot_count)	{
		printf("specified number of key slots to crack greater than active key slots in LUKS header. The number of active key slots is: %d\n", header.active_slot_count);
		return 1;
	}

	struct keyslot_password *passwords; 

	passwords = crack(header, wordlist_file, number_of_threads, number_of_slots);

	for (i=0; i < number_of_slots; i++)	{
		if (passwords[i].password)	{
			printf("Found password '%s'\n for keyslot %d\n", passwords[i].password, ++passwords[i].keyslot_index);
			free(passwords[i].password);
		}
		else
			printf("exhausted wordlist for keyslot %d\n", passwords[i].keyslot_index);
	}

	free(passwords);

	for (i=0; i < header.active_slot_count; i++)
		free(header.active_key_slots[i]->key_data);

	fclose(header_file);
	fclose(wordlist_file);

	return 0;
}
