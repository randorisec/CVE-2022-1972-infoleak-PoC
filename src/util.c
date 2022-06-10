#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>

#include "log.h"
#include "util.h"

/**
 * new_ns(): Create a new namespace in order to get the capability CAP_NET_ADMIN
 */
void new_ns(void) {

    if (unshare(CLONE_NEWUSER))
        do_error_exit("unshare(CLONE_NEWUSER)");

    if (unshare(CLONE_NEWNET))
        do_error_exit("unshare(CLONE_NEWNET)");

}
