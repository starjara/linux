#ifndef __MINI_TYPES_H__
#define __MINI_TYPES_H__


#include <linux/types.h>

struct mini;
struct mini_memslots;

typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;

#define INVALID_GPA	(~(gpa_t)0)

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;

#define MINI_STATS_NAME_SIZE	48

#endif
