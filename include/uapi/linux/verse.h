#ifndef __LINUX_VERSE_H__
#define __LINUX_VERSE_H__

#include <asm/verse.h>

#define VERSEIO 0xF3

#define VERSE_CREATE _IO(VERSEIO, 0x01)
#define VERSE_DESTROY _IO(VERSEIO, 0x02)

#define VERSE_ENTER _IO(VERSEIO, 0x11)
#define VERSE_EXIT _IO(VERSEIO, 0x12)

#define VERSE_MMAP _IO(VERSEIO, 0x21)
#define VERSE_MUNMAP _IO(VERSEIO, 0x22)
#define VERSE_MPROTECT _IO(VERSEIO, 0x23)

#endif // __LINUX_VERSE_H__
