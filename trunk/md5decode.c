#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static char *alpha;
static int alphaSize;
static int current_stringSize;
static uint32_t sMd5Key[4];

int TransformCompareMd5(uint32_t *key,uint32_t *in);
void loadMd5(uint32_t buf[4],char *md5Key);
static void showResult(uint32_t *in,int current_stringSize);

static void crack(int offset,uint32_t *in)
{
	if (offset >= current_stringSize)
	{
		if (TransformCompareMd5(sMd5Key, in))
			showResult(in, current_stringSize);
	}
	else
	{
		uint32_t j=alphaSize,i=j--;
		const uint32_t p = (offset << 3) & 24;
		for(;i--;)
		{
			in[offset >> 2] &= (uint32_t) ~ (0xFF <<  p); //Clear position of the new letter
			in[offset >> 2] += (uint32_t) alpha[j-i] << p; // Put the new letter on string
			crack(offset+1,in);
		}
	}
}

static void showResult(uint32_t *in,int current_stringSize){
	int i;
	char *keyFound=malloc(sizeof(char)*30);
	for (i = 0; i < current_stringSize; i++)
		keyFound[i]=in[i >> 2]>>((i & 3)<<3);
	keyFound[current_stringSize]='\0';
	printf("Match string found: %s\n",keyFound);
	exit(0);
}

struct thread_data{
        int tam;
	char initChar;
};
static struct thread_data *thread_data_array;

static void callCrack_thread(void *threadarg){
	struct thread_data *my_data;
        my_data = (struct thread_data *) threadarg;
	uint32_t in[6];
        in[5] = ((uint32_t)my_data->tam << 3);
        in[my_data->tam/4]=0x80<<(((my_data->tam)%4)<<3);
	in[0]=(uint32_t)my_data->initChar;
	current_stringSize=my_data->tam;
        crack(1,in);
}


static void callCrack_size(int size){
        int j;
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
	char alphaType = (char)*argv[1];
	const int minS = (int)atoi(argv[2]);
	const int maxS = (int)atoi(argv[3]);
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
        int i;
        for (i=0; i < 33; i++)
        	md5Key[i] = (char)tolower(argv[4][i]); //better than strcpy(md5Key, argv[4]);

	printf("hash %s to be cracked\n",md5Key);
	loadMd5(sMd5Key,md5Key);
	alphaSize=(int)strlen(alpha);
	thread_data_array=malloc(sizeof(struct thread_data)*alphaSize);

	for (i=minS;i <= maxS;i++){
		callCrack_size(i);
		printf("no results to size:%d\n",i);
	}
	printf("failed:no results found\n");
	exit(1);
}

