//
// Created by ash on 1/12/23.
//

#include "ios.h"
#include "ios_auxtbl.h"

#ifndef MINUTE_BOOT1

#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "elf.h"

// expressed as offsets
struct free_space {
    u32 space;
    u32 space_top;
};

static const char *ios_module_names[14] = {
        "IOS-KERNEL", "IOS-MCP", "IOS-BSP", "IOS-CRYPTO", "IOS-USB", "IOS-FS", "IOS-PAD",
        "IOS-NET", "IOS-ACP", "IOS-NSEC", "IOS-AUXIL", "IOS-NIM-BOSS", "IOS-FPD", "IOS-TEST"
};

static u32 relocate_load(Elf32_Phdr* phdr, struct free_space *free_space, void* ios, FILE* f_module)
{
    if (free_space->space + phdr->p_filesz >= free_space->space_top) {
        printf("ios: ran out of space while loading module!\n");
        return -1;
    }

    // read data into new location at end of IOS image
    fseek(f_module, phdr->p_offset, SEEK_SET);
    fread((void*)ios + free_space->space, 1, phdr->p_filesz, f_module);

    // update phdr file offset to new location (end of IOS image)
    phdr->p_offset = free_space->space;
    free_space->space += phdr->p_filesz;

    printf("ios: moved module phdr %08x to %08x (size %08x)\n", phdr->p_vaddr, phdr->p_offset, phdr->p_filesz);
    return 0;
}

// returns: the NOTE section
static Elf32_Phdr* replace_phdrs_for_uid(int uid, Elf32_Phdr* ios_phdrs, u16* ios_phnum, Elf32_Phdr* mod_phdrs, u16 mod_phnum) {
    Elf32_Phdr *note = NULL;

    u16 next_mod_phdr = 0;
    if (next_mod_phdr >= mod_phnum) return NULL;

    for (int i = 0; i < *ios_phnum; i++) {
        Elf32_Phdr* phdr = &ios_phdrs[i];

        if (phdr->p_type == PT_NOTE) {
            note = phdr;
            continue;
        }
        if (phdr->p_flags >> 20 != uid) {
            continue;
        }

        printf("ios: phdr %d (%08x) belongs to %s\n", i, phdr->p_vaddr, ios_module_names[uid]);

        while (next_mod_phdr < mod_phnum) {
            if (mod_phdrs[next_mod_phdr].p_type == PT_LOAD) {
                break;
            }
            next_mod_phdr++;
        }

        if (next_mod_phdr < mod_phnum) {
            Elf32_Phdr *m_phdr = &mod_phdrs[next_mod_phdr];
            printf("ios: replacing with module phdr %d (%08x / %08x)\n", next_mod_phdr, m_phdr->p_vaddr, m_phdr->p_filesz);

            *phdr = *m_phdr;
            phdr->p_flags |= (uid << 20);

            next_mod_phdr++;
        } else {
            printf("ios: removing it\n");

//            memset(phdr, 0, sizeof(*phdr));
            printf("ios: before: i %d phnum %d\n", i, *ios_phnum);
            // this is prooobably wrong
            memmove(phdr, phdr + 1, ((*ios_phnum)-- - (i + 1)) * sizeof(Elf32_Phdr));
            i--;
            printf("ios: after: i %d phnum %d\n", i, *ios_phnum);
        }
    }

    return note;
}

static u32 fixup_note_section(int uid, Elf32_Phdr* note, void* ios, Elf32_Ehdr* module, u32 stack_addr, u32 stack_sz) {
    struct ios_auxtbl_entry* auxtbl = ios + note->p_offset + 0xC;

    if (auxtbl[uid].v_pid != uid) {
        printf("ios: aux table looks corrupt\n");
        return -1;
    }

    auxtbl[uid].v_entry = module->e_entry;
    auxtbl[uid].v_stackaddr = stack_addr;
    auxtbl[uid].v_stacksize = stack_sz;

    return 0;
}

static u32 ios_module_load(int uid, const char* module_path, struct free_space *free_space, Elf32_Ehdr* ios)
{
    FILE *f_module = fopen(module_path, "rb");
    if (!f_module) {
        // doesn't exist
        return 1;
    }

    printf("ios: Replacing %s with %s\n", ios_module_names[uid], module_path);

    Elf32_Ehdr mod;
    fread(&mod, 1, sizeof(mod), f_module);
    // todo validate the elf :sunglasses:
    // well. any error checking would be nice really
    if (sizeof(Elf32_Phdr) != mod.e_phentsize) {
        printf("ios: module has bad program headers!\n");
        fclose(f_module);
        return -1;
    }

    Elf32_Phdr mod_phdrs[mod.e_phnum];
    fseek(f_module, mod.e_phoff, SEEK_SET);
    fread(mod_phdrs, sizeof(mod_phdrs[0]), mod.e_phnum, f_module);

    u32 stack_addr = 0;
    u32 stack_sz = 0;

    for (int i = 0; i < mod.e_phnum; i++) {
        if (mod_phdrs[i].p_type != PT_LOAD) continue;

        int ret = relocate_load(&mod_phdrs[i], free_space, (void*)ios, f_module);
        if (ret < 0) {
            fclose(f_module);
            return ret;
        }

        u32* loaded_data = (void*)ios + mod_phdrs[i].p_offset;
        if (loaded_data[0] == 0x5354434B /* "STCK" */) {
            stack_addr = loaded_data[1];
            stack_sz = loaded_data[2];
        }
    }

    fclose(f_module);
    f_module = NULL;

    if (!stack_sz) {
        printf("ios: couldn't find stack!\n");
        return -1;
    }

    Elf32_Phdr *ios_phdrs = (Elf32_Phdr*)((void*)ios + ios->e_phoff);
    Elf32_Phdr *note = replace_phdrs_for_uid(uid, ios_phdrs, &ios->e_phnum, mod_phdrs, mod.e_phnum);
    if (!note) {
        printf("ios: couldn't find NOTE section!\n");
        return -1;
    }

    int ret = fixup_note_section(uid, note, (void*)ios, &mod, stack_addr, stack_sz);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

static struct free_space find_free_space() {
    void *ios_ancast = (void*)0x01000000;
    u32 ios_ancast_sz = *(u32*)(ios_ancast + 0x1AC);
    void *mem1_top = (void*)0x02000000;

    // we'll load the code into here
    // TODO probably worth trying to reclaim space from IOSU modules too
    void *free_space = ios_ancast + ios_ancast_sz;
    if (free_space >= mem1_top) {
        return (struct free_space) { 0, 0 };
    }
    return (struct free_space) { ios_ancast_sz, mem1_top - ios_ancast };
}

u32 ios_modules_load(const char* modules_fpath, u32 ios_base)
{
    struct free_space free_space = find_free_space();
    if (!free_space.space) {
        printf("ios: no space for modules!\n");
        return -1;
    }
    printf("ios: %d KiB free for modules.\n", (free_space.space_top - free_space.space) / 1024);

    Elf32_Ehdr *ios = (Elf32_Ehdr*)ios_base;
    if (ios->e_phentsize != sizeof(Elf32_Phdr)) {
        printf("ios: BUG: Program headers are %d bytes instead of %d?\n", ios->e_phentsize, sizeof(Elf32_Phdr));
        return -1;
    }

    const int path_max_len = strlen(modules_fpath) + sizeof("/IOS-NIM-BOSS.elf") + 1;

    for (int i = 0; i < ARR_SIZE(ios_module_names); i++) {
        char module_path[path_max_len];
        snprintf(module_path, path_max_len-1, "%s/%s.elf", modules_fpath, ios_module_names[i]);

        int ret = ios_module_load(i, module_path, &free_space, ios);
        if (ret < 0) return ret;
    }

    return 0;
}

#endif //MINUTE_BOOT1
