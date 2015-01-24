#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static char *alpha;
static int alphaSize;
static int current_stringSize;
static uint32_t *pKey;
#ifdef CONFIG_MD5
int HashSumAndCompare(uint32_t *key,uint32_t *in);
#else
int HashSumAndCompare(uint32_t *key,uint32_t *in, int len);
#endif
void loadHash(uint32_t *buf,char *strKey);

static void crack(int offset,char *in){
	if (offset >= current_stringSize)
	{
		#ifdef CONFIG_MD5
			if (HashSumAndCompare(pKey, (void*)in)){
		#else
			if (HashSumAndCompare(pKey, (void*)in, current_stringSize)){
		#endif
			in[current_stringSize]='\0';
			printf("Match string found: %s\n",in);
			exit(0);
		}
	}
	else
	{
		int i;
		for(i=0;i<=alphaSize;i++)
		{
			in[offset] = alpha[i]; // Put letter on string
			crack(offset+1,in);
		}
	}
}

struct thread_data{
        int tam;
	char initChar;
};
static struct thread_data *thread_data_array;

static void callCrack_thread(void *threadarg){
	struct thread_data *my_data;
        my_data = (struct thread_data *) threadarg;
	char in[19];
	#ifdef CONFIG_MD5
		uint32_t *iin = (void *)in;
     		iin[5] = ((uint32_t)my_data->tam << 3); /* FIXME: This is the ugliest code of ever */
		in[my_data->tam]=0x80;
	#endif
	in[0]=my_data->initChar;
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
		printf ("%s [caAdx] min max hash\n", argv[0]);
		exit(1);
	}
	
	#ifdef CONFIG_MD5
		int hashSize = 32;
	#else	
		#ifdef CONFIG_SHA3
			int hashSize = 128;
		#else
			#ifdef CONFIG_SHA256
				int hashSize = 64;
			#else
				int hashSize = 40;	
			#endif
		#endif
	#endif


	char strKey[hashSize];
	uint32_t Key[hashSize]; //It stores the hashkey in array of int
	pKey=Key;

	char alphaType = (char)*argv[1];
	const int minS = (int)atoi(argv[2]);
	const int maxS = (int)atoi(argv[3]);
	switch (alphaType)
	{	
		case 'c':
			alpha = "eaorinsltcmdhugp"; //Most commons chars in passwords
			break;
		case 'a':
			alpha = "eaorinsltcmdhbugpykfwvjzxq";
			break;
		case 'A':
//eaorinsltcmdhbug1pykfwv2j30z45x9678qKQFZX
			alpha = "aedbcfghijklmnopqrstuvwxyzAENROIBCDFGHJKLMPQSTUVWXYZ";
			break;
		case 'd':
			alpha = "aeoidbcfghjklmnpqrstuvwxyz123AENROIBCDFGHJKLMPQSTUVWXYZ0456789";
			//alpha = "eaorinsltcmdhbug1pykfwv2j30z45x9678qKQFZX";
			break;
		case 'x':
//eaorinsltcmdhbug1pykfwv2j30z45x9678qEALSONIRMJCYUTDPHGWVB!KQF#@ZX$
			alpha = "aedbcfghsijklmnopqrtuvwxyz123AEDBCFGHIJKLMNOPQRSTUVWXYZ0456789$#@!\"%&/()=?-.:\\*'-_:;, ";
			break;
		default :
			printf ("%s [caAdx] min max hash\n", argv[0]);
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
	if ((unsigned int) strlen(argv[4]) != (unsigned int) hashSize){
                printf ("%s [caAdx] min max hash(%d chars 0-9A-F)\n", argv[0], hashSize);
                exit(1);
        }
        int i;
        for (i=0; i <= hashSize; i++)
        	strKey[i] = (char)tolower(argv[4][i]); //better than strcpy(strKey, argv[4]);

	printf("hash %s to be cracked\n",strKey);
	loadHash(pKey,strKey);
	alphaSize=(int)strlen(alpha);
	thread_data_array=malloc(sizeof(struct thread_data)*alphaSize);

	for (i=minS;i <= maxS;i++){
		callCrack_size(i);
		printf("no results to size:%d\n",i);
	}
	printf("failed:no results found\n");
	exit(1);
}

