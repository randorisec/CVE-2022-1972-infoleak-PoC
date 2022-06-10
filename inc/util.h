#ifndef _UTIL_H_
#define _UTIL_H_

#define ALIGN(v, a) (((v) + (a) - 1) & ~((a) - 1))

void new_ns(void);

#endif /* _UTIL_H_ */
