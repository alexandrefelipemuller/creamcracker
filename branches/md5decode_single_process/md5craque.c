#include <stdio.h>
#include "Md5.c"

int crack(int sizeString,char *md5Key,char *alpha,char *append){
	unsigned int i,len = strlen(alpha);
	for (i=0; i < len; i++)
	{
		append[sizeString-1] = alpha[i]; //add new char
		if (sizeString > 1)
		{
			crack(sizeString-1,md5Key,alpha,append);
		}
		else
		{
			char *md5out = MDString(append);
			if (strncmp(md5Key,md5out,32) == 0)
			{
				printf("Match string found: %s\n",append);
				exit(1);
			}
			free(md5out);
		}
	}
}

int main (int argc, char *argv[]){
	if (argc != 5){
		printf ("%s [aAdx] min max md5\n", argv[0]);
		exit(1);
	}
	char md5Key[32];
	char alphaType = *argv[1];
	int minS = atoi(argv[2]);
	int maxS = atoi(argv[3]);
	strcpy(md5Key, argv[4]);
	char *alpha;
	switch (alphaType)
	{
		case 'a':
			alpha = "abcdefghijklmnopqrstuvwxyz";
			break;
		case 'A':
			alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
			break;
		case 'd':
			alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			break;
		case 'x':
			alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"$%&/()=?-.:\\*'-_:;, ";
			break;
		default :
		    printf ("%s [aAdx] min max md5\n", argv[0]);
                    exit(1);
       }
	printf("hash %s to be cracked\n",md5Key);
	unsigned int i;
	char *temp;
	for (i=minS; i <= maxS; i++){
		printf("testing size:%d\n",i);
		temp=calloc(sizeof(char),i+1); //String full of \0
		crack(i,md5Key,alpha,temp);
	}
}
