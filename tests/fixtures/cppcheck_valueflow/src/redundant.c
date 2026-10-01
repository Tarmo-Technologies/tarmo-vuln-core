#include <stddef.h>

int deref_then_check(int *p)
{
    int v = *p;
    if (p == NULL) {
        return -1;
    }
    return v;
}

int index_after_check(int idx)
{
    int buf[10];
    buf[0] = 0;
    if (idx < 20) {
        return buf[idx];
    }
    return 0;
}

int read_uninit(void)
{
    int x;
    return x;
}
