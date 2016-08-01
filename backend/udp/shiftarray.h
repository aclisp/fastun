#ifndef __SHIFTARRAY_H__
#define __SHIFTARRAY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _lrad_shift_entry lrad_shift_entry;

struct _lrad_shift_entry {
    IUINT32 fr;
    IUINT32 to;
};

#define LRAD_SHIFT_TOINFI    0xFFFFFFFF
#define LRAD_SHIFT_INCIDX(i, m) ( (i) == (m)-1 ? (i)=0 : ++(i) )
#define LRAD_SHIFT_DECIDX(i, m) ( (i) == 0 ? (i)=(m)-1 : --(i) )
#define LRAD_SHIFT_LENGTH(f, t, m) ( (t) == LRAD_SHIFT_TOINFI ? (m) : \
                                     (t) == (f) ? (0) :               \
                                     (t) >  (f) ? ((t)-(f)) :         \
                                                  ((t)+(m)-(f)) )

IUINT32 lrad_shift_get_push_back_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt);
IUINT32 lrad_shift_get_push_front_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt);
IUINT32 lrad_shift_get_pop_back_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt);
IUINT32 lrad_shift_get_pop_front_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SHIFTARRAY_H__ */
