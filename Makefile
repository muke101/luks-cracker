CC=gcc
STANDARD=-Ofast -pipe -march=native -fomit-frame-pointer -fdevirtualize-at-ltrans     
WARNINGS=-Wall -Wextra -Wno-unused-result -Wno-unused-variable -Wno-unused-parameter
LTO=-flto=4
GRAPHITE=-fgraphite-identity -floop-nest-optimize -floop-interchange -ftree-loop-distribution -floop-strip-mine -floop-block
SECURITY=-no-pie -fno-stack-protector -fno-stack-clash-protection
IPA=-fipa-pta

LIBS = -lcrypto
OBJ = parser.o

CFLAGS =$(STANDARD) $(LTO) $(GRAPHITE) $(IPA) $(SECURITY) $(WARNINGS) 

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o parser
