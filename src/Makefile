CC=gcc
STANDARD=-Ofast -pipe -march=native -fomit-frame-pointer -fdevirtualize-at-ltrans 
WARNINGS=-Wall -Wextra -Wno-unused-result -Wno-unused-variable -Wno-unused-parameter
LTO=-flto=10
GRAPHITE=-fgraphite-identity -floop-nest-optimize -floop-interchange -ftree-loop-distribution -floop-strip-mine -floop-block
SECURITY=-no-pie -fno-stack-protector -fno-stack-clash-protection
IPA=-fipa-pta

IDIR=../include
_DEPS = parser.h cracker.h
DEPS= $(patsubst %,$(IDIR)/%,$(_DEPS))

LIBS = -lcrypto

OBJ = parser.o cracker.o main.o

CFLAGS =$(STANDARD) $(LTO) $(GRAPHITE) $(IPA) $(SECURITY) $(WARNINGS) -I$(IDIR) 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

../lukscrack: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o ../lukscrack
