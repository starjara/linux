#ifndef __MINI_HOST_H
#define __MINI_HOST_H

#define mini_info(fmt, ...) \
    pr_info("mini [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

#endif
