#ifndef __LINUX_VERSE_H__
#define __LINUX_VERSE_H__

#include <asm/verse.h>

#define VERSEIO 0xF3

#define VERSE_CREATE _IO(VERSEIO, 0x01)
#define VERSE_DESTROY _IO(VERSEIO, 0x02)

#define VERSE_ENTER _IO(VERSEIO, 0x11)
#define VERSE_EXIT _IO(VERSEIO, 0x12)

#define VERSE_MMAP _IOW(VERSEIO, 0x21, struct verse_memory_region)
#define VERSE_MUNMAP _IO(VERSEIO, 0x22)
#define VERSE_MPROTECT _IO(VERSEIO, 0x23)

#define VERSE_BULK_WRITE _IOW(VERSEIO, 0x31, struct verse_memory_region)
#define VERSE_BULK_READ _IOW(VERSEIO, 0x32, struct verse_memory_region)

struct verse_memory_region {
  __u64 guest_phys_addr;
  __u64 memory_size;
  __u64 userspace_addr;
  __u32 prot;
};

#endif // __LINUX_VERSE_H__
