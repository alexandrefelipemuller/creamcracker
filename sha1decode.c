#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int Sha1String(uint32_t *SHA1KEY, unsigned char *inbuf, size_t inlen);
void loadSha1Int(char *sha1Key,uint32_t *SHA1KEY);

unsigned short int alphaSize;
unsigned int current_stringSize;
char *alpha;
uint32_t SHA1KEY[20];

void crack(int sizeString,unsigned char *append){
	unsigned int i;
	for (i=0; i < alphaSize; i++ )
	{
		append[sizeString-1] = alpha[i]; //add new char
		if (sizeString > 1)
		{
			crack(sizeString-1,append);
		}
		else
			if (Sha1String(SHA1KEY, append, current_stringSize))
			{
				printf("Match string found: %s\n",append);
				exit(0);
			}
	}
}

int main (int argc, char *argv[]){
	if (argc != 5){
		printf ("%s [aAdx] min max sha1\n", argv[0]);
		exit(1);
	}
	char strSHA1Key[40];
	char alphaType = *argv[1];
	unsigned int minS = atoi(argv[2]);
	unsigned int maxS = atoi(argv[3]);
	switch (alphaType)
	{
		case 'c':
			alpha = "aeosrnidmutcplgh"; //Most commons chars in passwords
			break;
		case 'a':
			alpha = "aedbcfghijklmnopqrstuvwxyz";
			break;
		case 'A':
			alpha = "aedbcfghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
			break;
		case 'd':
			alpha = "aedbcfghijklmnopqrstuvwxyz123ABCDEFGHIJKLMNOPQRSTUVWXYZ0456789";
			break;
		case 'x':
			alpha = "aedbcfghsijklmnopqrtuvwxyz123AEDBCFGHIJKLMNOPQRSTUVWXYZ0456789$#@!\"%&/()=?-.:\\*'-_:;, ";
			break;
		default :
		    printf ("%s [aAdx] min max sha1\n", argv[0]);
                    exit(1);
       }
	unsigned int i;
        for (i=0; i < 41; i++)
        	strSHA1Key[i] = (char)tolower(argv[4][i]); //better than strcpy(md5Key, argv[4]);
	printf("hash %s to be cracked\n",strSHA1Key);
	alphaSize = strlen(alpha);

	loadSha1Int(strSHA1Key,SHA1KEY);

	unsigned char *temp;
	for (current_stringSize=minS; current_stringSize <= maxS; current_stringSize++){
		printf("testing size:%d\n",current_stringSize);
		temp=calloc(sizeof(char),current_stringSize+1); //String full of \0
		crack(current_stringSize,temp);
	}
	exit(1);
}
