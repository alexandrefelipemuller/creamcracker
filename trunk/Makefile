#COMP=/opt/open64/bin/opencc -O2 
#COMP=clang -O2 
COMP=gcc # -O2 -Wall -Wextra -Werror -funsafe-loop-optimizations -fpredictive-commoning # -fprofile-use

MD5BIN=md5decode
SHA1BIN=sha1decode
all: $(MD5BIN) $(SHA1BIN)

./$(MD5BIN): md5decode.c md5.c
		$(COMP) -c md5.c -o md5.o
		$(COMP) -c md5decode.c -o md5decode.o
		$(COMP) md5decode.o md5.o -o $(MD5BIN) -lpthread
		strip ./$(MD5BIN)
./$(SHA1BIN): sha1decode.c sha1.c
		$(COMP) -c sha1.c -o sha1.o
		$(COMP) -c sha1decode.c -o sha1decode.o
		$(COMP) sha1decode.o sha1.o -o $(SHA1BIN) # -lpthread
		strip ./$(SHA1BIN)

clean:
		rm -f *~ core* *.o $(MD5BIN) $(SHA1BIN)

