#ifndef __LINUX_MINI_H
#define __LINUX_MINI_H

#include <linux/const.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/ioctl.h>
//#include <asm/mini.h>


#define MINIIO  0xF3

#define MINI_CREATE_VM      _IO(MINIIO, 0x01)
#define MINI_DEST_VM        _IO(MINIIO, 0x02)

#define MINI_ALLOC          _IO(MINIIO, 0x04)
#define MINI_FREE           _IO(MINIIO, 0x05)

#define MINI_ENTER          _IO(MINIIO, 0x09)
#define MINI_EXIT           _IO(MINIIO, 0x0a)

#endif
