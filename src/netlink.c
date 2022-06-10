#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#include "log.h"
#include "netlink.h"

/**
 * get_batch_begin_nlmsg(): Construct a BATCH_BEGIN message for the netfilter netlink
 */
struct nlmsghdr *get_batch_begin_nlmsg(void) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nfgenmsg)));
    struct nfgenmsg *nfgm = (struct nfgenmsg *)NLMSG_DATA(nlh);

    if (!nlh) {
        do_error_exit("malloc");
    }

    memset(nlh, 0, NLMSG_SPACE(sizeof(struct nfgenmsg)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
    nlh->nlmsg_type = NFNL_MSG_BATCH_BEGIN;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq = 0;

    /* Used to access to the netfilter tables subsystem */
    nfgm->res_id = NFNL_SUBSYS_NFTABLES;

    return nlh;
}

/**
 * get_batch_end_nlmsg(): Construct a BATCH_END message for the netfilter netlink
 */
struct nlmsghdr *get_batch_end_nlmsg(void) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nfgenmsg)));

    if (!nlh) {
        do_error_exit("malloc");
    }

    memset(nlh, 0, NLMSG_SPACE(sizeof(struct nfgenmsg)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
    nlh->nlmsg_type = NFNL_MSG_BATCH_END;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;

    return nlh;
}

/**
 * set_nested_attr(): Prepare a nested netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the nested attribute
 * @data_len: Length of the nested attribute
 */
struct nlattr *set_nested_attr(struct nlattr *attr, uint16_t type, uint16_t data_len) {
    attr->nla_type = type;
    attr->nla_len = data_len + NLA_HDRLEN;
    return (void *)attr + NLA_HDRLEN;
}

/**
 * set_u32_attr(): Prepare an integer netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the attribute
 * @value: Value of this attribute
 */
struct nlattr *set_u32_attr(struct nlattr *attr, uint16_t type, uint32_t value) {
    attr->nla_type = type;
    attr->nla_len = U32_NLA_SIZE;
    *(uint32_t *)NLA_ATTR(attr) = htonl(value);

    return (void *)attr + U32_NLA_SIZE;
}

/**
 * set_str8_attr(): Prepare a 8 bytes long string netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the attribute
 * @name: Buffer to copy into the attribute
 */
struct nlattr *set_str8_attr(struct nlattr *attr, uint16_t type, const char name[8]) {
    attr->nla_type = type;
    attr->nla_len = S8_NLA_SIZE;
    memcpy(NLA_ATTR(attr), name, 8);

    return (void *)attr + S8_NLA_SIZE;
}
