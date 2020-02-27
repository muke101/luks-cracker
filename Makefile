CC=gcc
STANDARD=-O2 -pipe -march=native -fomit-frame-pointer -fdevirtualize-at-ltrans     
WARNINGS=-Wall -Wextra -Wno-unused-result -Wno-unused-variable -Wno-unused-parameter
LTO=-flto=10
GRAPHITE=-fgraphite-identity -floop-nest-optimize -floop-interchange -ftree-loop-distribution -floop-strip-mine -floop-block
IPA=-fipa-pta

LIBS = -lcrypto
OBJ = parser.o

CFLAGS =$(STANDARD) $(LTO) $(GRAPHITE) $(IPA) $(WARNINGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o parser
