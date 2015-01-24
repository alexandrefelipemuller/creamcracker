#COMP=/opt/open64/bin/opencc -O2 
#COMP=clang -O2 
#COMP=gcc -O2 -Wall -Wextra -Werror -funsafe-loop-optimizations -fpredictive-commoning # -fprofile-use -mtune=nocona -march=nocona 
COMP=gcc -O2 -funsafe-loop-optimizations -fpredictive-commoning # -fprofile-use -mtune=nocona -march=nocona 


MD5BIN=bin/md5decode
SHA1BIN=bin/sha1decode
SHA256BIN=bin/sha256decode
SHA3BIN=bin/sha3decode

all: $(MD5BIN) $(SHA1BIN) $(SHA256BIN) $(SHA3BIN)

./$(MD5BIN): hash_decode.c md5.c
		$(COMP) -c md5.c -o md5.o
		$(COMP) -D CONFIG_MD5 -c hash_decode.c -o md5decode.o
		$(COMP) md5decode.o md5.o -o $(MD5BIN) -lpthread
		strip ./$(MD5BIN)
./$(SHA1BIN): hash_decode.c sha1.c
		$(COMP) -c sha1.c -o sha1.o
		$(COMP) -c hash_decode.c -o sha1decode.o
		$(COMP) sha1decode.o sha1.o -o $(SHA1BIN) -lpthread
		strip ./$(SHA1BIN)
./$(SHA256BIN): hash_decode.c sha256.c
		$(COMP) -c sha256.c -o sha256.o
		$(COMP) -D CONFIG_SHA256 -c hash_decode.c -o sha256decode.o
		$(COMP) sha256decode.o sha256.o -o $(SHA256BIN) -lpthread
		strip ./$(SHA256BIN)

./$(SHA3BIN): hash_decode.c sha3.c
		$(COMP) -std=c99 -c sha3.c -o sha3.o
		$(COMP) -D CONFIG_SHA3 -c hash_decode.c -o sha3decode.o
		$(COMP) sha3decode.o sha3.o -o $(SHA3BIN) -lpthread
		strip ./$(SHA3BIN)

clean:
		rm -f *~ core* *.o $(MD5BIN) $(SHA1BIN)

