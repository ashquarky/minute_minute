//
// Created by ash on 1/12/23.
//

#ifndef MINUTE_MINUTE_IOS_AUXTBL_H
#define MINUTE_MINUTE_IOS_AUXTBL_H

#include "types.h"

typedef enum AuxTblEntryType {
    AT_ENTRY = 9,
    AT_UID = 11,
    AT_PRIORITY = 125,
    AT_STACK_SIZE = 126,
    AT_STACK_ADDR = 127,
    AT_MEM_PERM_MASK = 128
} AuxTblEntryType;

struct ios_auxtbl_entry { /* (actually an array of auxv_t entries, this was only made to simplify) */
    u32 t_pid;
    u32 v_pid;

    u32 t_entry;
    u32 v_entry;

    u32 t_priority;
    u32 v_priority;

    u32 t_stacksize;
    u32 v_stacksize;

    u32 t_stackaddr;
    u32 v_stackaddr;

    u32 t_memperm;
    u32 v_memperm;
};

#endif //MINUTE_MINUTE_IOS_AUXTBL_H
