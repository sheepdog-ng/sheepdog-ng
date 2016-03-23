/*
 * Copyright (C) 2016 China Mobile Inc.
 *
 * Gui Hecheng <guihecheng@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIVEPATCH_H_
#define __LIVEPATCH_H_

#define INSN_SIZE       5       /* call(1b) + offset(4b) = 5b */

#ifndef __ASSEMBLY__

#include <stdbool.h>
#include <elf.h>
#include "list.h"

#define __init __attribute__ ((__section__ (".lp_init_text")))
#define __exit __attribute__ ((__section__ (".lp_exit_text")))

#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_R_SYM   ELF64_R_SYM
#define ELF_R_TYPE  ELF64_R_TYPE

struct livepatch_func {
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
	char *name;
	struct list_node list;
	struct hlist_node node;
};

struct livepatch_dynrela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
	char *name;
	int addend;
	struct list_node list;
};

struct livepatch_patch;

typedef unsigned long long u64;
typedef unsigned int u32;
typedef long long s64;
typedef int s32;

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym  Elf_Sym;
typedef Elf64_Rela Elf_Rela;

typedef int (*initcall_t)(void);
typedef void (*exitcall_t)(void);

struct livepatch_initexit {
    initcall_t init;
    exitcall_t exit;
};

struct elf_layout {
    /* The actual code + data. */
    void *base;
    /* Total size. */
    unsigned int size;
    /* The size of the executable code.  */
    unsigned int text_size;
    /* Size of RO section text+rodata) */
    unsigned int ro_size;
};

struct livepatch_elf {
    Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct {
        unsigned int sym, str;
    } index;
    struct livepatch_initexit *initexit;
    struct elf_layout core_layout;
    struct elf_layout init_layout;

    /* extracted from patch file */
    struct livepatch_patch *patch_struct;
};

struct livepatch_file {
    char *name;
    char *path;
    unsigned long size;
    int fd;
    void *mem;
    struct livepatch_elf *elf;
};

struct livepatch_patch {
	struct livepatch_file *file;
	struct list_head funcs;
	struct list_head dynrelas;
	struct list_node list;
};

void __fentry__(void);
void livepatch_caller(void);
void livepatch_handler(unsigned long, unsigned long *);

#ifdef HAVE_LIVEPATCH
  int livepatch_patch(const char *patch);
  int livepatch_unpatch(const char *patch);
  size_t livepatch_status(char *buf);
  int livepatch_init(const char *base_path);
#else
  static inline int livepatch_patch(const char *patch) { return 0; }
  static inline int livepatch_unpatch(const char *patch) { return 0; }
  static inline int livepatch_init(const char *base_path) { return 0; }
  static inline size_t livepatch_status(char *buf) { return 0; }
#endif /* HAVE_LIVEPATCH */

#endif /* __ASSEMBLY__ */
#endif /* __LIVEPATCH_H_ */
