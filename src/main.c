#include "parser.h"
#include "cracker.h"

int main(int argc, char **argv)	{
	struct phdr header;
	char *drive = *++argv;
	FILE *fp;

	fp = fopen(drive, "r");

	if (fp && is_luks_header(fp))
		header = parse_header(fp);
	else	{
		printf("invalid header\n");
		return 1;
	}

	crack(header);

	return 0;
}
