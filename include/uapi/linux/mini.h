#ifndef __LINUX_MINI_H
#define __LINUX_MINI_H

#include <linux/const.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/ioctl.h>

#include <asm/mini.h>

#define MINI_API_VERSION 1

#define MINI_MEM_READONLY	(1UL << 1)

#define MINIIO  0xF3

#define MINI_GET_API_VERSION_      _IO(MINIIO, 0x00)
#define MINI_CREATE_VM      _IO(MINIIO, 0x01)
#define MINI_DEST_VM        _IO(MINIIO, 0x02)

#define MINI_GET_VCPU_MMAP_SIZE    _IO(MINIIO,   0x04) /* in bytes */

#define VERSE_MMAP          _IOW(MINIIO, 0x05, \
				struct kvm_userspace_memory_region)
#define MINI_FREE           _IO(MINIIO, 0x06)

#define MINI_ENTER          _IO(MINIIO, 0x09)
#define MINI_EXIT           _IO(MINIIO, 0x0a)

#define VERSE_MAP_EXECUTABLE         _IOW(MINIIO, 0x0b, struct kvm_userspace_memory_region)
#define VERSE_UNMAP_EXECUTABLE         _IO(MINIIO, 0x0c)

#define MINI_CREATE_VCPU           _IO(MINIIO,   0x41)

#define MINI_SET_USER_MEMORY_REGION _IOW(MINIIO, 0x46, \
					struct kvm_userspace_memory_region)

#define MINI_MEM_LOG_DIRTY_PAGES	(1UL << 0)
#define MINI_MEM_READONLY	(1UL << 1)

/*
struct mini_userspace_memory_region {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; // bytes 
	__u64 userspace_addr; // start of the userspace allocated memory 
};

struct mini_stats_header {
	__u32 flags;
	__u32 name_size;
	__u32 num_desc;
	__u32 id_offset;
	__u32 desc_offset;
	__u32 data_offset;
};

#define MINI_STATS_TYPE_SHIFT		0
#define MINI_STATS_TYPE_MASK		(0xF << MINI_STATS_TYPE_SHIFT)
#define MINI_STATS_TYPE_CUMULATIVE	(0x0 << MINI_STATS_TYPE_SHIFT)
#define MINI_STATS_TYPE_INSTANT		(0x1 << MINI_STATS_TYPE_SHIFT)
#define MINI_STATS_TYPE_PEAK		(0x2 << MINI_STATS_TYPE_SHIFT)
#define MINI_STATS_TYPE_LINEAR_HIST	(0x3 << MINI_STATS_TYPE_SHIFT)
#define MINI_STATS_TYPE_LOG_HIST		(0x4 << MINI_STATS_TYPE_SHIFT)
#define MINI_STATS_TYPE_MAX		MINI_STATS_TYPE_LOG_HIST

#define MINI_STATS_UNIT_SHIFT		4
#define MINI_STATS_UNIT_MASK		(0xF << MINI_STATS_UNIT_SHIFT)
#define MINI_STATS_UNIT_NONE		(0x0 << MINI_STATS_UNIT_SHIFT)
#define MINI_STATS_UNIT_BYTES		(0x1 << MINI_STATS_UNIT_SHIFT)
#define MINI_STATS_UNIT_SECONDS		(0x2 << MINI_STATS_UNIT_SHIFT)
#define MINI_STATS_UNIT_CYCLES		(0x3 << MINI_STATS_UNIT_SHIFT)
#define MINI_STATS_UNIT_BOOLEAN		(0x4 << MINI_STATS_UNIT_SHIFT)
#define MINI_STATS_UNIT_MAX		MINI_STATS_UNIT_BOOLEAN

#define MINI_STATS_BASE_SHIFT		8
#define MINI_STATS_BASE_MASK		(0xF << MINI_STATS_BASE_SHIFT)
#define MINI_STATS_BASE_POW10		(0x0 << MINI_STATS_BASE_SHIFT)
#define MINI_STATS_BASE_POW2		(0x1 << MINI_STATS_BASE_SHIFT)
#define MINI_STATS_BASE_MAX		MINI_STATS_BASE_POW2

struct mini_stats_desc {
	__u32 flags;
	__s16 exponent;
	__u16 size;
	__u32 offset;
	__u32 bucket_size;
	char name[];
};

#ifndef MINI_DIRTY_LOG_PAGE_OFFSET
#define MINI_DIRTY_LOG_PAGE_OFFSET 0
#endif
#define MINI_DIRTY_LOG_INITIALLY_SET            (1 << 1)
*/

#endif
