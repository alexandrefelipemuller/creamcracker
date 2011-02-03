#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

char *alpha;
unsigned short int alphaSize;
unsigned int current_stringSize;
uint32_t sMd5Key[4];

void showResult(uint32_t *in, unsigned int current_stringSize);
int TransformCompareMd5(uint32_t *key,uint32_t *in);
void loadMd5(uint32_t buf[4],char *md5Key);

void crack(unsigned int begin,uint32_t *in){
	if (begin < current_stringSize)
	{
		uint32_t i,j=alphaSize-1;
		uint32_t p = (begin << 3) & 24;
		for(i=alphaSize;i--;)
		{
			in[begin >> 2] &= (uint32_t) ~ (0xFF <<  p); //Clear position of the new letter
			in[begin >> 2] += (uint32_t) alpha[j-i] << p; // Put the new letter on string
			crack(begin+1,in);
		}
	}
	else
		if (TransformCompareMd5(sMd5Key, in))
		       showResult(in, current_stringSize);
}

void showResult(uint32_t *in,unsigned int current_stringSize){
	int i;
	char *keyFound=malloc(sizeof(char)*30);
	for (i = 0; i < 30; i++)
		keyFound[i]=in[i >> 2]>>((i & 3)<<3);
	keyFound[current_stringSize]='\0';
	printf("Match string found: %s\n",keyFound);
	exit(0);
}

struct thread_data{
        unsigned int tam;
	char initChar;
};
struct thread_data *thread_data_array;

void callCrack_thread(void *threadarg){
	struct thread_data *my_data;
        my_data = (struct thread_data *) threadarg;
	uint32_t in[16];
        in[14] = ((uint32_t)my_data->tam << 3);
        in[my_data->tam/4]=0x80<<(((my_data->tam)%4)<<3);
	in[0]=(uint32_t)in[0]|my_data->initChar;
	current_stringSize=my_data->tam;
        crack(1,in);
}


void callCrack_size(int size){
        unsigned int j;
	pthread_t request[alphaSize];
        for (j=0; j < alphaSize; j++)
        {
		thread_data_array[j].tam = size;
		thread_data_array[j].initChar = alpha[j];
		pthread_create(&request[j], NULL, (void*) callCrack_thread, &thread_data_array[j]);
	}
	for (j=0; j < alphaSize; j++){
                (void) pthread_join(request[j], NULL);
        }
	return;
}

int main (int argc, char *argv[]){
	if (argc != 5){
		printf ("%s [caAdx] min max md5\n", argv[0]);
		exit(1);
	}
	char md5Key[33];
	unsigned char alphaType = (unsigned char)*argv[1];
	unsigned int minS = (unsigned int)atoi(argv[2]);
	unsigned int maxS = (unsigned int)atoi(argv[3]);
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
			printf ("%s [caAdx] min max md5\n", argv[0]);
			exit(1);
	}

	if (maxS > 19){
		printf ("Maximum size not supported\nThe time to compute is senseless, even in the best world computer\n");
		exit(1);
	}
	if (minS < 1){
		printf ("Minimum size not supported\nThe key should have at least 1 char\n");
		exit(1);
	}
	if (strlen(argv[4]) != 32){
                printf ("%s [caAdx] min max md5(32 chars 0-9A-F)\n", argv[0]);
                exit(1);
        }
        unsigned int i;
        for (i=0; i < 33; i++)
        	md5Key[i] = (char)tolower(argv[4][i]); //better than strcpy(md5Key, argv[4]);

	printf("hash %s to be cracked\n",md5Key);
	loadMd5(sMd5Key,md5Key);
	alphaSize=(unsigned short int)strlen(alpha);
	thread_data_array=malloc(sizeof(struct thread_data)*alphaSize);

	for (i=minS;i <= maxS;i++){
		callCrack_size(i);
		printf("no results to size:%d\n",i);
	}
	printf("failed:no results found\n");
	exit(1);
}

