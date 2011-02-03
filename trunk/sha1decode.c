#include <stdio.h>

static char *Sha1String(unsigned char *inbuf, size_t inlen);

int crack(int sizeString,char *sha1Key,char *alpha,char *append){
	unsigned int i,len = strlen(alpha);
	for (i=0; i < len; i++)
	{
		append[sizeString-1] = alpha[i]; //add new char
		if (sizeString > 1)
		{
			crack(sizeString-1,sha1Key,alpha,append);
		}
		else
		{
			char *sha1out = Sha1String(append,strlen(append));
			if (strncmp(sha1Key,sha1out,32) == 0)
			{
				printf("Match string found: %s\n",append);
				exit(1);
			}
			free(sha1out);
		}
	}
}

int main (int argc, char *argv[]){
//	assert (sizeof (u32) == 4);

	if (argc != 5){
		printf ("%s [aAdx] min max sha1\n", argv[0]);
		exit(1);
	}
	char sha1Key[40];
	char alphaType = *argv[1];
	int minS = atoi(argv[2]);
	int maxS = atoi(argv[3]);
	strcpy(sha1Key, argv[4]);
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
		    printf ("%s [aAdx] min max sha1\n", argv[0]);
                    exit(1);
       }
	printf("hash %s to be cracked\n",sha1Key);
	unsigned int i;
	char *temp;
	for (i=minS; i <= maxS; i++){
		printf("testing size:%d\n",i);
		temp=calloc(sizeof(char),i+1); //String full of \0
		crack(i,sha1Key,alpha,temp);
	}
}
