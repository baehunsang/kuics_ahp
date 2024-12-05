#include <unistd.h>

int main() {
    char *args[] = { "/bin/sh", "-i", NULL };
    //소유궈자가 root여야 가능
    setgid(0);
    setuid(0);
    execve("/bin/sh", args, NULL);

    return 0;
}