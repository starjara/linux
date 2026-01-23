#ifndef __GBPF_H__
#define __GBPF_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/static_call.h>
#include <linux/bpf.h>

#include "gbpf_mmu.h"

#define gbpf_err(fmt, ...) \
    pr_err("[gBPF] [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define gbpf_info(fmt, ...) \
    pr_info("[gBPF] [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

//DECLARE_STATIC_CALL(gbpf_alloc_gpgd, void (*)(struct bpf_prog *));

#endif //__GBPF_H__
