#ifndef __VERSE_TYPES_H__
#define __VERSE_TYPES_H__

struct verse;

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;

#define INVALID_GPA	(~(gpa_t)0)

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;


#endif // __VERSE_TYPSE_H__
