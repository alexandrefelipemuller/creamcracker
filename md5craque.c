#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "Md5.c"
#define true (1==1)
#define false !true

int pid,ppid;
int crack(int sizeString,char *md5Key,char *alpha,char *append){
	int len = strlen(alpha);
	char *temp,*md5out;
	if (sizeString == 1){
		int i;
		for (i=0; i < len; i++)
		{
			temp=malloc(sizeof(char)*strlen(append)+2);
			temp[0] = alpha[i]; //add new char
			temp[1] = '\0';
			strcat(temp,append);
			md5out = malloc(sizeof(char)*33);
			MDString(temp,md5out);
			if (strncmp(md5Key,md5out,32) == 0)
			{
				printf("Match string found: %s\n",temp);
				if (pid!=0)
					kill(pid,SIGTERM);
				else
					kill(ppid,SIGTERM);
				exit(1);
			}
			free(temp);
			free(md5out);
		}
	}
	else
	{
		int i;
		for (i=0; i < len; i++){
			temp=malloc(sizeof(char)*(strlen(append)+2));
			temp[0] = alpha[i];
			temp[1] = '\0';
			crack(sizeString-1,md5Key,alpha,strcat(temp,append));
			free(temp);
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
	unsigned int i;
	ppid=getpid();
	pid=fork();
	if(pid==-1)
	{
		perror("Fork failed");
		exit(-1);
        }
	if(pid==0)
	{
		for (i=minS+1; i <= maxS; i+=2)
			crack(i,md5Key,alpha,"");
	}
	else
	{
		for (i=minS; i <= maxS; i+=2)
			crack(i,md5Key,alpha,"");
	}

}
