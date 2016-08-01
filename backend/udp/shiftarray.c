#include "ikcp.h"
#include "shiftarray.h"

IUINT32 lrad_shift_get_push_back_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt)
{
    IUINT32 index;
    size_t length = LRAD_SHIFT_LENGTH(*pfr, *pto, maxcnt);

    if(length == maxcnt) {
        index = *pfr;
        LRAD_SHIFT_INCIDX(*pfr, maxcnt);
    } else {
        index = *pto;
        length == maxcnt-1 ? *pto = LRAD_SHIFT_TOINFI :
            LRAD_SHIFT_INCIDX(*pto, maxcnt);
    }

    return index;
}

IUINT32 lrad_shift_get_push_front_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt)
{
    IUINT32 index;
    size_t length = LRAD_SHIFT_LENGTH(*pfr, *pto, maxcnt);

    if(length == maxcnt) {
        index = LRAD_SHIFT_DECIDX(*pfr, maxcnt);
    } else {
        if(length == maxcnt-1)
            *pto = LRAD_SHIFT_TOINFI;
        index = LRAD_SHIFT_DECIDX(*pfr, maxcnt);
    }

    return index;
}

IUINT32 lrad_shift_get_pop_back_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt)
{
    IUINT32 index;
    size_t length = LRAD_SHIFT_LENGTH(*pfr, *pto, maxcnt);

    if(length == maxcnt) {
        *pto = *pfr;
        index = LRAD_SHIFT_DECIDX(*pto, maxcnt);
    } else if(length == 0) {
        index = LRAD_SHIFT_TOINFI;
    } else {
        index = LRAD_SHIFT_DECIDX(*pto, maxcnt);
    }

    return index;
}

IUINT32 lrad_shift_get_pop_front_index(
    IUINT32 *pfr, IUINT32 *pto, size_t maxcnt)
{
    IUINT32 index;
    size_t length = LRAD_SHIFT_LENGTH(*pfr, *pto, maxcnt);

    if(length == maxcnt) {
        index = *pfr;
        *pto = *pfr;
        LRAD_SHIFT_INCIDX(*pfr, maxcnt);
    } else if(length == 0) {
        index = LRAD_SHIFT_TOINFI;
    } else {
        index = *pfr;
        LRAD_SHIFT_INCIDX(*pfr, maxcnt);
    }

    return index;
}
