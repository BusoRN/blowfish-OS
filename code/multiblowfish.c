#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include "blowfish.h"
#define SLICE_SIZE_MAX 3000000 	// Maximum slice size to save RAM
#define SHOW_TIME

/*
 * 		GLOBAL VARIABLE
 */
unsigned short mode; 		//! it is 0 if the user want to encript, 1 to decript

int threads_number;		//! number of threads that will be generated

long int input_file_size;	//! Size of input file
long int block_size;		//! Block size in bytes.

/*	SLICE	   */
long int slice_number;		//! Number of subblock owned by block.
long int slice_size;		//! Dimension of each slice


FILE *input_fp;			//! Input file descriptor.
FILE *output_fp;		//! Output file descriptor.

BLOWFISH_CTX *ctx;		//! Context for the Blowfish algorithm generated using the provided key.

/* To perform read and write operation we need to make access to two different file, so we need two mutex for ensuring mutual exclusion */
pthread_mutex_t reader_mutex;	// reader mutex
pthread_mutex_t writer_mutex;	// writer mutex

/* In order to perform the reminder handling inside the whloe block we need to know the dimension of reminder, and the dimension of reminder multiple of 8*/
long int reminder_slice_size; 
long int reminder_slice_size_mul8;
char *output_file_name;
	

//This structure is used to pass parameters to the threads
struct thread_params{
	unsigned long start;
	unsigned long stop;
};


// Prototype
void *runner_blowfish(void *args);
uint64_t Blowfish_call(BLOWFISH_CTX *ctx, uint64_t x);
uint64_t Decrypt(BLOWFISH_CTX *ctx, uint64_t x);



#ifdef SHOW_TIME
/*
 * Used to tested the code, it allows to show the processed time
 */
int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
  return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}
#endif


/**
 * This is the main function of the whole project.
 * 	int main(int argc, char *argv[]) 
 * 
 * @param argc argument counter
 * @param argv argument vector
 * 
 * @note user may use the function in twi different ways:
 * 	 without input arguments (they will be given in a second time)--> multithreads-blowfish
 * 	 with input argument --> multithreads-blowfish -(e|d) input_file_name output_file_name threads_number key
 */
int main(int argc, char **argv) 
{
	pthread_t *tid;//pointer to threads ID
	struct thread_params *tp;//parameters to the threads 
	char* op_mode; // variable where the operational mode will be stored, it may assume -e or -d
	char *input_file_name;//here will be stored the name of input file
	char *key;//user key used for coding & decoding
	int key_length;//here will be stored the key length in byte
	long int reminder_size; //here the size of reminder is stored
	long int reminder_size_mul8; //here the size of reminder has be made multiple of 8
	int padding; //here padding dimension will be stored
	uint64_t input_rem;//reminder read from input file
	uint64_t output_rem;//reminder that has to be written on output file
	long int begin_rem;//here the base address of reminder (resulted from block division) will be stored
	
	
	/******************************/
	/*     Looking for inputs    */
	/*****************************/
	
	if((argc != 1) && (argc != 6))
	{
		perror("ARGUMENTS ERROR\n");
		exit(EXIT_FAILURE);
	}
	if(argc == 1)
	{
		// in this case no inputs are given by command line, so they have to be inserted by the user right now
		//malloc operations are required
		op_mode = (char*) malloc(3*sizeof(char));
		output_file_name = (char*) malloc(20*sizeof(char));
		input_file_name = (char*) malloc(20*sizeof(char));
		key = (char*) malloc(56*sizeof(char));
		
		printf("Hello! You have to insert some inputs.\n");
		printf("Please, insert the operational mode (''-e'' for encription, and ''-d'' for decripion):\n");
		scanf("%s",op_mode);
		fflush(stdin);
		
		printf("Please, insert the input file name:\n");
		scanf("%s",input_file_name);
		fflush(stdin);
		
		printf("Please, insert the output file name:\n");
		scanf("%s",output_file_name);
		fflush(stdin);
				
		printf("Please, insert the number of threads that will be created:\n");
		scanf("%d",&threads_number);
		fflush(stdin);
		
		printf("Please, insert the own key:\n");
		scanf("%s",key);
		fflush(stdin);
	}
	else
	{
		// in this other case the five parameters are given by command line
		op_mode = argv[1];
		input_file_name = argv[2];
		output_file_name = argv[3];
		threads_number = atoi(argv[4]);
		key = argv[5];
	}
	
	if(strncmp(op_mode, "-e",2) == 0)
	{
		mode = 0;
	}
	else if(strncmp(op_mode, "-d",2) == 0)
	{
		mode = 1;
	}
	else
	{
		perror("ERROR: please, insert a correct operation mode");
		exit(EXIT_FAILURE);
	}
	
	if(threads_number < 1)
	{
		perror("ERROR: please insert a number of threads greater than zero\n");
		exit(EXIT_FAILURE);
	}
	
	
	input_fp = fopen(input_file_name, "rb"); //opens the input file as read only in binary mode
	if(input_fp == NULL)
	{
		perror("ERROR occured opening the input file\n");
		exit(EXIT_FAILURE);
	}
	
	output_fp = fopen(output_file_name, "wb+");//opens the output file as read/write in binary mode
	if(output_fp == NULL)
	{
		perror("ERROR occured opening the output file\n");
		exit(EXIT_FAILURE);
	}
	
	//check the size of the key
	key_length = strlen(key);	
	if((key_length<4) || (key_length>56))
	{
		// Out of 32-448 bits range
		perror("ERROR: please, insert a key which has the size from 4 to 56 bytes");
		exit(EXIT_FAILURE);
	}
	

#ifdef SHOW_TIME
	struct timespec start_time, end_time;
	clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif	
	
	ctx = (BLOWFISH_CTX *) malloc(sizeof(BLOWFISH_CTX));
	Blowfish_Init(ctx, key, key_length);// Create Blowfish's context for the session.
	
	
	
	
	/*****************************/
	/*     File subdivision      */
	/*****************************/
	
	input_file_size = 0;
	
	fseek(input_fp, 0, SEEK_END); // seek to end of file
	input_file_size = ftell(input_fp); // get current file pointer, so it returns the size of input file in bytes
	fseek(input_fp, 0, SEEK_SET); // seek back to beginning of file
	// checking the file dimension, that has to be bigger that 64 bits--> 8 bytes
	if(input_file_size < 8)
	{
		perror("ERROR: please, insert a file which has size up to 8 bytes\n");
		exit(EXIT_FAILURE);
	}
	
	
	block_size = input_file_size / threads_number;	// Distribute equally the load to the threads.
	if(0 != (block_size%8))
	{
		// Make the block size multiple of 64 bits, the main thread will take care of the reminder.
		block_size -= (block_size%8);
	}
	
	reminder_size = input_file_size - (block_size * threads_number);// Reminder size 
	reminder_size_mul8 = reminder_size - (reminder_size%8);// Reminder size multiple of 8 bytes
	padding = 8 - (reminder_size%8);//Padding dimension
	//printf("padding %d\n", padding_size);
	
	if(slice_size < SLICE_SIZE_MAX)
	{
		slice_size = block_size;
		slice_number = 1;
	}
	else
	{
		/* Block dimension si bigger than the maximum allowed, so we need divide it */
		slice_size = SLICE_SIZE_MAX;//slice size is given by the max allowed
		slice_number = block_size / slice_size;//so here the number of slice per block is stored
		reminder_slice_size = block_size - (slice_size * slice_number);	//reminder size 
		reminder_slice_size_mul8 = reminder_slice_size_mul8 - (reminder_slice_size%8);//reminder size multiple of 8
	}
	
	
	/******************************/
	/*           Threads          */
	/*****************************/
	
	tid = (pthread_t *) malloc(threads_number * sizeof(pthread_t));	
	tp = (struct thread_params *) malloc(threads_number * sizeof(struct thread_params));
	pthread_mutex_init(&reader_mutex, NULL);
	pthread_mutex_init(&writer_mutex, NULL);
	
	int i = 0;
	for(i = 0; i < threads_number; i++)
	{

		tp[i].start = i*block_size;
		tp[i].stop = tp[i].start + block_size; 
		if(pthread_create(&tid[i], NULL, runner_blowfish, (void *)(&tp[i])))
		{
			perror("ERROR: occured during thread creation\n");
			exit(EXIT_FAILURE);
		}
	}
	
	
	
	/******************************/
	/*      Reminder handling     */
	/*****************************/
	begin_rem = tp[threads_number-1].stop;//start address of the reminder is given by the last one of last thread
	
	
	for(i = 0; i<reminder_size_mul8; i += 8)
	{
		pthread_mutex_lock(&reader_mutex);
			fseek(input_fp, begin_rem+i, SEEK_SET);
			fread(&input_rem, 8, 1, input_fp); //FREAD FOR READING IN BINARY MODE
		pthread_mutex_unlock(&reader_mutex);
		
		output_rem = Blowfish_call(ctx, input_rem);
		
	//	if(i = reminder_size_aligned -8)
	//		printf("out_data_rem lettura %ld\n", out_data_rem);
		
		
		pthread_mutex_lock(&writer_mutex);
			fseek(output_fp, begin_rem+i, SEEK_SET);
			fwrite(&output_rem, 8, 1, output_fp);
		pthread_mutex_unlock(&writer_mutex);
		
	}
	
	/* Wait till all of the threads have finished their jobs*/
	int index;
	for(index = 0; index < threads_number; index++)
	{
		pthread_join(tid[index], NULL);// Wait all the thread to finish their work before proceeding.
	}
	
	//From this point the mutex are useless since only the main thread is still alive
	
	/******************************/
	/*           Padding          */
	/*****************************/
	
	if(mode == 0)
	{
		fseek(input_fp, begin_rem+reminder_size_mul8, SEEK_SET);//points to the base of the last data which are less than 8 byte
		fread(&input_rem, reminder_size-reminder_size_mul8, 1, input_fp);
		
		for(index = reminder_size-reminder_size_mul8; index < 8; ++index)
		{
			input_rem = input_rem & ~( (uint64_t)(0xFF) << 8*index);//Ensure that the last byte are null
			input_rem = input_rem | ( ((uint64_t)padding) << 8*index);	// write the padding
		}
		
		//printf("in_data_rem %ld\n", in_data_rem);
		
		output_rem = Blowfish_call(ctx, input_rem);
		

		fseek(output_fp, begin_rem+i, SEEK_SET);
		fwrite(&output_rem, 8, 1, output_fp);
	}
	else
	{
		// Last 8 bytes already decrypted  along with the padding which have to be trimmed, its length is written as padding data (at most 8 byte).
		fseek(output_fp, input_file_size-8, SEEK_SET);
		fread(&output_rem, 8, 1, output_fp);
		//printf("out_data_rem %ld\n", out_data_rem);
		uint64_t dummy_bytes = output_rem & ((uint64_t)0xFF<<8*7);//number of bytes that has to be removed because reppresent the padding
		dummy_bytes >>= (8*7);
		//printf("trim %ld\n", trim_len);
		fclose(output_fp);
		truncate(output_file_name, input_file_size-dummy_bytes);// removes the padding from the file
	}
	
	

	
	
#ifdef SHOW_TIME	
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	double Computation_time = (double)timespecDiff(&end_time, &start_time);// from difference between end time and start time we perform the computation time.
	printf("Computation time: %f seconds.\n", Computation_time/1000000000);
#endif
	
	
	/* Ending */
	
	free(tid);
	free(tp);
	
	pthread_mutex_destroy(&reader_mutex);
	pthread_mutex_destroy(&writer_mutex);	
	fcloseall();
	

	exit(0);
}

/**
 * This is the thread function
 * 	void *runner_blowfish(void *args)
 * 
 * @param args a struct that gives the start and stop address to thread funcion
 */
void *runner_blowfish(void *args)
{
	struct thread_params *p = (struct thread_params *) args;
	long int pointer = 0;
	uint64_t *buffer = (uint64_t *)malloc(slice_size);
	int index;
	uint64_t input_rem_frame;
	uint64_t output_rem_frame;
	
	for(pointer = 0; pointer<block_size; pointer += slice_size)
	{
		// Read the slice and store it in RAM
		pthread_mutex_lock(&reader_mutex);
			fseek(input_fp, p->start+pointer, SEEK_SET);
			fread(buffer, slice_size, 1, input_fp);
		pthread_mutex_unlock(&reader_mutex);
		
		for(index = 0; index < (slice_size/sizeof(uint64_t)); ++index)
		{
			buffer[index] = Blowfish_call(ctx, buffer[index]);

		}
		
		// after computation the fram has to be written in output file
		pthread_mutex_lock(&writer_mutex);
			fseek(output_fp, p->start+pointer, SEEK_SET);
			fwrite(buffer, slice_size, 1, output_fp);
			if(ferror(output_fp))
			{
				perror("Writing error\n");
				exit(EXIT_FAILURE);
			}
		pthread_mutex_unlock(&writer_mutex);
	}
	
	if(block_size > SLICE_SIZE_MAX)
	{
		/* REMINDER */
		//also the thread has to manage a reminder
		long int base_rem_frame = p->start + slice_number * slice_size;	
		
		int i;
	
		for(i = 0; i<reminder_slice_size_mul8; i += 8)
		{
			//Elabora la parte del reminder del frame che non ha bisogno del padding
			pthread_mutex_lock(&reader_mutex);
				fseek(input_fp, base_rem_frame+i, SEEK_SET);
				fread(&input_rem_frame, 8, 1, input_fp);
			pthread_mutex_unlock(&reader_mutex);

			output_rem_frame = Blowfish_call(ctx, input_rem_frame);
		
			pthread_mutex_lock(&writer_mutex);
				fseek(output_fp, base_rem_frame+i, SEEK_SET);
				fwrite(&output_rem_frame, 8, 1, output_fp);
				if(ferror(output_fp))
				{
					perror("Writing error\n");
					exit(EXIT_FAILURE);
				}
			pthread_mutex_unlock(&writer_mutex);
		}
	
		buffer = (uint64_t *) memset(buffer, 0, slice_size);// For security reasons overwrite memory before exiting
		free(buffer);
		pthread_exit(NULL);
	}
}

/**
 * This is the wrapper of blowfish
 * 	uint64_t Blowfish_call(BLOWFISH_CTX *ctx, uint64_t x)
 * 
 * @param ctx blowfish's context
 * @param x 8 bytes of block to be encrypted or decrypted
 * @return 8 bytes of encrypted or decrypted block
 */
uint64_t Blowfish_call(BLOWFISH_CTX *ctx, uint64_t x)
{
	uint32_t L = (x>>32);
	uint32_t R = (uint32_t)(x & 0x0000000FFFFFFFF);
	
	if(mode == 0)
	{
		Blowfish_Encrypt(ctx, &L, &R);
	}
	else
	{
		Blowfish_Decrypt(ctx, &L, &R);
	}
	
	return ((uint64_t)L<<32) | R;
}