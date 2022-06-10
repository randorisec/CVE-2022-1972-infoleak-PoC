#ifndef _LEAK_H_
#define _LEAK_H_

#include <util.h>

#define LEAK_BASE 0x14
#define LEAK_SIZE 0x30
#define LEAK_BUFFER_SIZE ALIGN(LEAK_SIZE - LEAK_BASE, sizeof(long))

void get_leak(int sock, const char *table_name, const char *set_name);

#endif /* _LEAK_H_ */
