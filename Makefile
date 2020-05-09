
CC = gcc
ZLIB = -lz
FUSELIB = -lfuse -lpthread -ldl
SQLITE_OPT = -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION
SQLITE_OPT += -DSQLITE_OMIT_SHAREDCACHE -DSQLITE_HAS_CODEC 
SQLITE_OPT += -D_FILE_OFFSET_BITS=64


all: esqlar esqlarfs

esqlar: sqlar.c sqlite3.o
	$(CC) -o esqlar $(SQLITE_OPT) sqlar.c sqlite3.o $(FUSELIB) $(ZLIB)
	strip esqlar

esqlarfs: sqlarfs.c sqlite3.o
	$(CC) -o esqlarfs $(SQLITE_OPT) sqlarfs.c sqlite3.o $(FUSELIB) $(ZLIB)
	strip esqlarfs

sqlite3.o: sqlite3.c sqlite3.h codec.c
	$(CC) $(SQLITE_OPT) -c codec.c -o sqlite3.o

clean:	
	rm -f esqlar esqlarfs sqlite3.o zz zzc
