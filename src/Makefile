CC=gcc
STANDARD=-Ofast -pipe -march=native -fomit-frame-pointer -fdevirtualize-at-ltrans 
WARNINGS=-Wall -Wextra -Wno-unused-result -Wno-unused-variable -Wno-unused-parameter
LTO=-flto=10
GRAPHITE=-fgraphite-identity -floop-nest-optimize -floop-interchange -ftree-loop-distribution -floop-strip-mine -floop-block
SECURITY=-no-pie -fno-stack-protector -fno-stack-clash-protection
IPA=-fipa-pta
TESTTHREADS=-fsanitize=undefined,thread
TESTADDRESS=-fsanitize=undefined,address

IDIR=../include
_DEPS = parser.h cracker.h crypto_backend.o
DEPS= $(patsubst %,$(IDIR)/%,$(_DEPS))

LIBS = -lcrypto -lpthread

OBJ = parser.o cracker.o crypto_backend.o main.o

CFLAGS =$(STANDARD) $(LTO) $(GRAPHITE) $(IPA) $(SECURITY) $(WARNINGS) -I$(IDIR) $(TEST) 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

../lukscrack: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o ../lukscrack
