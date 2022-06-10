#ifndef _NETLINK_H_
#define _NETLINK_H_

#include <stdint.h>
#include <linux/netlink.h>

/* Netlink messages */

struct nlmsghdr *get_batch_begin_nlmsg(void);
struct nlmsghdr *get_batch_end_nlmsg(void);

/* Netlink attributes */

#define U32_NLA_SIZE (NLA_HDRLEN + sizeof(uint32_t))
#define S8_NLA_SIZE (NLA_HDRLEN + 8)
#define NLA_ATTR(attr) ((void *)attr + NLA_HDRLEN)

struct nlattr *set_nested_attr(struct nlattr *attr, uint16_t type, uint16_t data_len);
struct nlattr *set_u32_attr(struct nlattr *attr, uint16_t type, uint32_t value);
struct nlattr *set_str8_attr(struct nlattr *attr, uint16_t type, const char name[8]);

#endif /* _NETLINK_H_ */
