#include <stdio.h>
#include <string.h>

/* Bytes hexdumped at end of assembly code */
#define LEN 40
char *s = "\xb1\xd3\x32\x4c\xfc\xe6\xef\x5e\xed\xe4\x66\xcd\x57\xf5\xe1\x7f\xcd\x7f\x55\xf6\xe9\x64\xe7\xc9\x7f\x75\xe9\x54\xe6\x4d\xf7\x79\xfc\xfc\x51\x71\xf9\x3e\x18\xd9\x00";

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

uint16_t ror2(uint16_t x, int n)
{
    uint16_t shifted = x >> n;
    uint16_t rot_bits = x << (16-n);
    return shifted | rot_bits;
}

uint32_t ror4(uint32_t x, int n)
{
    uint32_t shifted = x >> n;
    uint32_t rot_bits = x << (32-n);
    return shifted | rot_bits;
}

uint16_t rol2(uint16_t x, int n)
{
    uint16_t shifted = x >> (16-n);
    uint16_t rot_bits = x << n;
    return shifted | rot_bits;
}

uint32_t rol4(uint32_t x, int n)
{
    uint32_t shifted = x >> (32-n);
    uint32_t rot_bits = x << n;
    return shifted | rot_bits;
}

int main(void)
{
    int i;
    uint32_t i32;
    uint16_t i16;
    char *p;

    char buf[LEN + 1];
    strncpy(buf, s, LEN + 1);

    for (i = LEN - 4; i >= 0; i--)
    {
	    p = &buf[i];
	    i32 = *(uint32_t*)p;
	    i32 = ror4(i32, 15);
	    *(uint32_t*)p = i32;
	    i16 = *(uint16_t*)p;
	    i16 = rol2(i16, 13);
	    *(uint16_t*)p = i16;
	    *p = *p ^ 0xde;
    }

    printf("%s\n", buf);

    return 0;
}
