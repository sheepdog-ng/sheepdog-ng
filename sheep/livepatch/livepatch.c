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

#include <elf.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>

#include "util.h"
#include "list.h"
#include "rbtree.h"
#include "logger.h"
#include "bitops.h"
#include "lookup.h"
#include "sheep_priv.h"
#include "livepatch.h"

#define ARCH_SHF_SMALL 0
#define ALIGN_MASK(x, mask)    (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK((x), (typeof(x))(a) - 1)
#define INIT_OFFSET_MASK (1UL << (BITS_PER_LONG - 1))

static const char *exe_path;
static char *patch_path;

static LIST_HEAD(patch_list);

#define PATCH_HASH_BITS 8
#define PATCH_HASH_SIZE (1 << (PATCH_HASH_BITS))
static struct hlist_head *patched_func_table;

static struct lookup_table *table;

union instruction {
	unsigned char start[INSN_SIZE];
	struct {
		char opcode;
		int offset;
	} __attribute__((packed));
};

static unsigned char *get_new_call(unsigned long ip, unsigned long addr)
{
	static union instruction code;

	code.opcode = 0xe8; /* opcode of call */
	code.offset = (int)(addr - ip - INSN_SIZE);

	return code.start;
}

static void replace_call(unsigned long ip, unsigned long func)
{
	unsigned char *new;

	new = get_new_call(ip, func);
	memcpy((void *)ip, new, INSN_SIZE);
}

static inline unsigned int patch_hash(unsigned long addr)
{
    return (unsigned int)(sd_hash_64(addr) % PATCH_HASH_SIZE);
}

static void register_patched_func(struct livepatch_func *func)
{
    unsigned int hval = patch_hash(func->old_addr);

    sd_info("register function (%s) old_addr %lu, new_addr %lu",
            func->name, func->old_addr, func->new_addr);

    hlist_add_head(&func->node, patched_func_table + hval);
}

static void unregister_patched_func(struct livepatch_func *func)
{
    sd_info("unregister function (%s) old_addr %lu, new_addr %lu",
            func->name, func->old_addr, func->new_addr);

    hlist_del(&func->node);
}

/* magic happens here */
__attribute__((no_instrument_function))
void livepatch_handler(unsigned long old_addr, unsigned long *new_addr)
{
    unsigned int hval = patch_hash(old_addr);
    struct livepatch_func *func = NULL;
    struct hlist_node *iter;

    hlist_for_each_entry(func, iter, patched_func_table + hval, node) {
        if (func->old_addr == old_addr)
            break;
    }

    if (!func) {
        sd_err("no such function %lu found to direct, go back to original",
               old_addr);
        return;
    }

    *new_addr = func->new_addr + INSN_SIZE;

    sd_debug("direct old function %lu to new function %lu", old_addr, *new_addr);
}

/* section header address from offset in file to offset in memory */
static int rewrite_section_headers(struct livepatch_elf *elf)
{
    elf->sechdrs[0].sh_addr = 0;

    for (unsigned int i = 1; i < elf->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &elf->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS
            && elf->len < shdr->sh_offset + shdr->sh_size) {
            sd_err("invalid section header");
            return -1;
        }

        shdr->sh_addr = (unsigned long)elf->hdr + shdr->sh_offset;
    }

    return 0;
}

static unsigned int find_sec(struct livepatch_elf *elf, const char *name)
{
	unsigned int i;

	for (i = 1; i < elf->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &elf->sechdrs[i];
		/* Alloc bit cleared means "ignore it." */
		if ((shdr->sh_flags & SHF_ALLOC)
		    && strcmp(elf->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static long get_offset(unsigned int *size, Elf_Shdr *sechdr)
{
	long ret;

	ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
	*size = ret + sechdr->sh_size;
	return ret;
}

static void layout_sections(struct livepatch_elf *elf)
{
	static unsigned long const masks[][2] = {
		/* NOTE: all executable code must be the first section
		 * in this array; otherwise modify the text_size
		 * finder in the two loops below */
		{ SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
		{ SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
		{ SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
		{ ARCH_SHF_SMALL | SHF_ALLOC, 0 }
	};
	unsigned int m, i;

	for (i = 0; i < elf->hdr->e_shnum; i++)
		elf->sechdrs[i].sh_entsize = ~0UL;

	sd_debug("Core section allocation order:");
	for (m = 0; m < ARRAY_SIZE(masks); ++m) {
		for (i = 0; i < elf->hdr->e_shnum; ++i) {
			Elf_Shdr *s = &elf->sechdrs[i];
			const char *sname = elf->secstrings + s->sh_name;

			if ((s->sh_flags & masks[m][0]) != masks[m][0]
			    || (s->sh_flags & masks[m][1])
			    || s->sh_entsize != ~0UL
			    || !strncmp(sname, ".lp_init_text", 13))
				continue;
			s->sh_entsize = get_offset(&elf->core_layout.size, s);
			sd_debug("\t%s", sname);
		}
		switch (m) {
		case 0: /* executable */
			elf->core_layout.text_size = elf->core_layout.size;
			break;
		case 1: /* RO: text and ro-data */
			elf->core_layout.ro_size = elf->core_layout.size;
			break;
		case 3: /* whole core */
			break;
		}
	}

	sd_debug("Init section allocation order:");
	for (m = 0; m < ARRAY_SIZE(masks); ++m) {
		for (i = 0; i < elf->hdr->e_shnum; ++i) {
			Elf_Shdr *s = &elf->sechdrs[i];
			const char *sname = elf->secstrings + s->sh_name;

			if ((s->sh_flags & masks[m][0]) != masks[m][0]
			    || (s->sh_flags & masks[m][1])
			    || s->sh_entsize != ~0UL
			    || strncmp(sname, ".lp_init_text", 13))
				continue;
			s->sh_entsize = get_offset(&elf->init_layout.size, s)
                            | INIT_OFFSET_MASK;
			sd_debug("\t%s", sname);
		}
		switch (m) {
		case 0: /* executable */
			elf->init_layout.text_size = elf->init_layout.size;
			break;
		case 1: /* RO: text and ro-data */
			elf->init_layout.ro_size = elf->init_layout.size;
			break;
		case 3: /* whole init */
			break;
		}
	}
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs,
                            unsigned int shnum)
{
    const Elf_Shdr *sec;

    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum
                                   || !src->st_name)
        return false;

    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || (sec->sh_entsize & INIT_OFFSET_MASK))
        return false;

    return true;
}


static void layout_symbols(struct livepatch_elf *elf)
{
	Elf_Shdr *symsect = elf->sechdrs + elf->index.sym;
	Elf_Shdr *strsect = elf->sechdrs + elf->index.str;
	const Elf_Sym *src;
	unsigned int i, nsrc, ndst, strtab_size = 0;

	/* Put symbol section at end of init part */
	symsect->sh_flags |= SHF_ALLOC;
	symsect->sh_entsize = get_offset(&elf->init_layout.size, symsect) | INIT_OFFSET_MASK;
	sd_debug("\t%s", elf->secstrings + symsect->sh_name);

	src = (Elf_Sym *)((char *)elf->hdr + symsect->sh_offset);
	nsrc = symsect->sh_size / sizeof(*src);

	/* Compute total space required for the core symbols' strtab. */
	for (ndst = i = 0; i < nsrc; i++) {
		if (i == 0 ||
		    is_core_symbol(src + i, elf->sechdrs, elf->hdr->e_shnum)) {
			strtab_size += strlen(&elf->strtab[src[i].st_name]) + 1;
			ndst++;
		}
	}

	/* Append room for core symbols at end of core part */
	elf->symoffs = ALIGN(elf->core_layout.size, symsect->sh_addralign ?: 1);
	elf->stroffs = elf->core_layout.size = elf->symoffs + ndst * sizeof(Elf_Sym);
	elf->core_layout.size += strtab_size;

	/* Put string table section at end of init part */
	strsect->sh_flags |= SHF_ALLOC;
	strsect->sh_entsize = get_offset(&elf->init_layout.size, strsect) | INIT_OFFSET_MASK;
	sd_debug("\t%s", elf->secstrings + strsect->sh_name);
}

static int make_text_available(void *ptr, unsigned int size)
{
    unsigned long start = (unsigned long)ptr & ~(getpagesize() - 1);

    return mprotect((void *)start, size, PROT_READ | PROT_EXEC | PROT_WRITE);
}

static int alloc_and_move(struct livepatch_elf *elf)
{
	int i;
	void *ptr;

	/* Do the allocs. */
	ptr = xvalloc(elf->core_layout.size);
	elf->core_layout.base = ptr;

	if (elf->init_layout.size) {
		ptr = xvalloc(elf->init_layout.size);
		elf->init_layout.base = ptr;
	} else
		elf->init_layout.base = NULL;

	/* Transfer each section which specifies SHF_ALLOC */
	sd_debug("final section addresses:\n");
	for (i = 0; i < elf->hdr->e_shnum; i++) {
		void *dest;
		Elf_Shdr *shdr = &elf->sechdrs[i];

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		if (shdr->sh_entsize & INIT_OFFSET_MASK)
			dest = (char *)elf->init_layout.base
	                + (shdr->sh_entsize & ~INIT_OFFSET_MASK);
		else
			dest = (char *)elf->core_layout.base + shdr->sh_entsize;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

		/* Update sh_addr to point to copy in image. */
		shdr->sh_addr = (unsigned long)dest;
		sd_debug("\t0x%lx %s",
                (long)shdr->sh_addr, elf->secstrings + shdr->sh_name);
	}

    if (make_text_available(elf->core_layout.base, elf->core_layout.size) < 0) {
        sd_err("failed to make core text executable (%m)");
        return -1;
    }
    if (make_text_available(elf->init_layout.base, elf->init_layout.size) < 0) {
        sd_err("failed to make init text executable (%m)");
        return -1;
    }

	return 0;
}

static struct livepatch_elf *layout_and_alloc(void *mem, unsigned long size)
{
    int ret;
    struct livepatch_elf *elf;
    unsigned int initexit_ndx, patch_struct_ndx;

    elf = xmalloc(sizeof(*elf));
    elf->hdr = mem;
    elf->len = size;
    elf->sechdrs = (Elf_Shdr *)((char *)elf->hdr + elf->hdr->e_shoff);
    elf->secstrings = (char *)elf->hdr
                        + elf->sechdrs[elf->hdr->e_shstrndx].sh_offset;
    memset(&elf->core_layout, 0, sizeof(elf->core_layout));
    memset(&elf->init_layout, 0, sizeof(elf->init_layout));
    ret = rewrite_section_headers(elf);
    if (ret) {
        sd_err("rewrite section header failed");
        goto err_free;
    }

    for (unsigned int i = 1; i < elf->hdr->e_shnum; i++) {
        if (elf->sechdrs[i].sh_type == SHT_SYMTAB) {
            elf->index.sym = i;
            elf->index.str = elf->sechdrs[i].sh_link;
            elf->strtab = (char *)elf->hdr
                            + elf->sechdrs[elf->index.str].sh_offset;
            break;
        }
    }

    if (elf->index.sym == 0) {
        sd_err("elf has no symbols (stripped ?)");
        goto err_free;
    }

    /* patch entrance & exit which build up & tear off patch info */
    initexit_ndx = find_sec(elf, ".lp_initexit");
    if (initexit_ndx == 0) {
        sd_err("elf has no init exit functions");
        goto err_free;
    }

    /* patch instance from patch-hook */
    patch_struct_ndx = find_sec(elf, ".lp_patch_struct");
    if (patch_struct_ndx == 0) {
        sd_err("elf has no patch struct");
        goto err_free;
    }

    layout_sections(elf);
    layout_symbols(elf);

    ret = alloc_and_move(elf);
    if (ret) {
        sd_err("failed to alloc and move elf to final place");
        goto err_free;
    }

    elf->initexit = (void *)elf->sechdrs[initexit_ndx].sh_addr;
    elf->patch_struct = (void *)elf->sechdrs[patch_struct_ndx].sh_addr;

    return elf;

err_free:
    free(elf);
    return NULL;
}

static int lookup_symbol(char *name, unsigned int bind, char *hint,
                         struct lookup_result *result)
{
    switch (bind) {
        case STB_LOCAL:
            return lookup_local_symbol(table, name, hint, result);
        case STB_GLOBAL:
            return lookup_global_symbol(table, name, result);
        default:
            return -1;
    }
}

static int verify_symbol(char *name, unsigned long addr)
{
    return lookup_exist_symbol(table, name, addr);
}

static int simplify_symbols(struct livepatch_elf *elf)
{
	Elf_Shdr *symsec = &elf->sechdrs[elf->index.sym];
	Elf_Sym *sym = (Elf_Sym *)symsec->sh_addr;
	unsigned long secbase;
    struct lookup_result result;
    char *hint = NULL;

    for(unsigned int i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        char *name = elf->strtab + sym[i].st_name;

        switch(sym[i].st_shndx) {
            case SHN_COMMON:
                sd_warn("Common symbol: %s", name);
                break;
            case SHN_ABS:
                sd_debug("Absolute symbol %s: 0x%08lx", name, (long)sym[i].st_value);
                if (ELF_ST_TYPE(sym[i].st_info) == STT_FILE)
                    hint = name;
                break;
            case SHN_UNDEF:
                if (lookup_symbol(name, ELF_ST_BIND(sym[i].st_info),
                                  hint, &result)) {
                    if (ELF_ST_BIND(sym[i].st_info) == STB_WEAK)
                        break;
                    sd_warn("Unresolved symbol: %s", name);
                    break;
                }
                sym[i].st_value = result.value;
                break;
            default:
                secbase = elf->sechdrs[sym[i].st_shndx].sh_addr;
                sym[i].st_value += secbase;
                break;
        }
    }

    return 0;
}

static int apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab,
                              unsigned int symindex, unsigned int relsec)
{
    unsigned int i;
	Elf_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	Elf_Sym *sym;
    void *loc;
	u64 val;

	sd_debug("Applying relocate section %u to %u",
	        relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		loc = (void *)((char *)sechdrs[sechdrs[relsec].sh_info].sh_addr
            + rel[i].r_offset);

		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf_Sym *)sechdrs[symindex].sh_addr
			+ ELF_R_SYM(rel[i].r_info);

        char *name = (char *)strtab + sym->st_name;

		sd_debug("symbol (%s) type %d st_value 0x%Lx r_addend 0x%Lx loc 0x%Lx",
		        name, (int)ELF_R_TYPE(rel[i].r_info),
		        (u64)sym->st_value, (u64)rel[i].r_addend, (u64)loc);

        /* FIXME: special case for __fentry__ */
        if (!strcmp("__fentry__", name)) {
            *(u32 *)loc = 0;
            continue;
        }

		val = sym->st_value + rel[i].r_addend;

		switch (ELF_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_64:
			*(u64 *)loc = val;
			break;
		case R_X86_64_32:
			*(u32 *)loc = val;
			if (val != *(u32 *)loc)
				goto overflow;
			break;
		case R_X86_64_32S:
			*(s32 *)loc = val;
			if ((s64)val != *(s32 *)loc)
				goto overflow;
			break;
		case R_X86_64_PC32:
			val -= (u64)loc;
			*(u32 *)loc = val;
			break;
		default:
			sd_debug("skip rela relocation: %llu",
	                (u64)ELF_R_TYPE(rel[i].r_info));
            break;
		}
	}
	return 0;

overflow:
	sd_err("overflow in relocation type %d val %Lx",
	       (int)ELF_R_TYPE(rel[i].r_info), (u64)val);
	return -1;
}

static int apply_relocations(struct livepatch_elf *elf)
{
    int ret;

    for (unsigned int i = 0; i < elf->hdr->e_shnum; i++) {
        unsigned int infosec = elf->sechdrs[i].sh_info;

        if (infosec >= elf->hdr->e_shnum)
            continue;

        if (!(elf->sechdrs[infosec].sh_flags & SHF_ALLOC))
            continue;

        if (elf->sechdrs[i].sh_type == SHT_RELA) {
            ret = apply_relocate_add(elf->sechdrs, elf->strtab, elf->index.sym, i);
            if (ret) {
                sd_err("apply relocation failed");
                break;
            }
        }
    }

    return ret;
}

static struct livepatch_elf *lp_elf_load(void *mem, unsigned long size)
{
    int ret;
    struct livepatch_elf *elf;

    elf = layout_and_alloc(mem, size);
    if (!elf) {
        sd_err("failed to init elf");
        goto err_free;
    }

    ret = simplify_symbols(elf);
    if (ret) {
        sd_err("failed to simplify symbols");
        goto err_free;
    }

    ret = apply_relocations(elf);
    if (ret) {
        sd_err("failed to apply relocations");
        goto err_free;
    }

    return elf;

err_free:
    free(elf);
    return NULL;
}

static struct livepatch_file *lp_file_load(const char *patchname)
{
    struct livepatch_file *file;
    struct stat st;
    char rpath[PATH_MAX];

    file = xmalloc(sizeof(*file));
    file->name = xstrdup(patchname);
    sprintf(rpath, "%s/%s", patch_path, patchname);
    file->path = xstrdup(rpath);

    if (!file->path) {
        sd_err("failed to get realpath of file %s (%m)", patchname);
        goto err_free_name;
    }

    file->fd = open(file->path, O_RDONLY | O_CLOEXEC);
    if (file->fd < 0) {
        sd_err("failed to open file %s (%m)", patchname);
        goto err_free_path;
    }

    if (fstat(file->fd, &st) < 0) {
        sd_err("failed to get file size %s (%m)", patchname);
        goto err_free_path;
    }

    file->size = st.st_size;

    file->mem = mmap(NULL, file->size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, file->fd, 0);
    if (file->mem == MAP_FAILED) {
        sd_err("failed to mmap file %s (%m)", patchname);
        goto err_free_path;
    }

    file->elf = lp_elf_load(file->mem, file->size);
    if (!file->elf) {
        sd_err("failed to load elf %s ", patchname);
        goto err_munmap;
    }

    return file;

err_munmap:
    munmap(file->mem, file->size);
err_free_path:
    free(file->path);
err_free_name:
    free(file->name);
    free(file);

    return NULL;
}

static void lp_elf_unload(struct livepatch_elf *elf)
{
    free(elf->core_layout.base);
    free(elf->init_layout.base);
}

static void lp_file_unload(struct livepatch_file *file)
{
    lp_elf_unload(file->elf);
    free(file->elf);
    munmap(file->mem, file->size);
    close(file->fd);
    free(file->path);
    free(file->name);
    free(file);
}

static struct livepatch_patch *lp_load(const char *patchname)
{
    int ret;
    struct livepatch_patch *patch;
    struct livepatch_file *file;

    file = lp_file_load(patchname);
    if (!file) {
        sd_err("failed to load file %s", patchname);
        goto out;
    }

    patch = file->elf->patch_struct;
    patch->file = file;

    initcall_t pinit = file->elf->initexit->init;
    ret = pinit();
    if (ret) {
        sd_err("failed to init patch %s", patchname);
        goto err_free;
    }

    return patch;

err_free:
    lp_file_unload(file);
out:
    return NULL;
}

static void lp_unload(struct livepatch_patch *patch)
{
    exitcall_t pexit = patch->file->elf->initexit->exit;
    pexit();

    lp_file_unload(patch->file);
}

/* make correct reference to symbols seen within functions */
static int write_relocations(struct livepatch_patch *patch)
{
    int size;
    u64 loc, val, core_start, core_size;
    struct livepatch_dynrela *dynrela;

    core_start = (u64)patch->file->elf->core_layout.base;
    core_size = (u64)patch->file->elf->core_layout.size;

    list_for_each_entry(dynrela, &patch->dynrelas, list) {
        if (verify_symbol(dynrela->name, dynrela->src)) {
            sd_err("symbol %s mismatch", dynrela->name);
            return -1;
        }

        sd_debug("write dynamic rela: name(%s) type(%ld) dest(0x%lx) src(0x%lx)",
                dynrela->name, dynrela->type, dynrela->dest, dynrela->src);

        switch(dynrela->type) {
            case R_X86_64_NONE:
                continue;
            case R_X86_64_PC32:
                loc = dynrela->dest;
                val = (u32)(dynrela->src + dynrela->addend
                                         - dynrela->dest);
                size = 4;
                break;
            case R_X86_64_32S:
                loc = dynrela->dest;
                val = (s32)dynrela->src + dynrela->addend;
                size = 4;
                break;
            case R_X86_64_64:
                loc = dynrela->dest;
                val = dynrela->src;
                size = 8;
                break;
            case R_X86_64_TPOFF32:
                loc = dynrela->dest;
                val = (u32)(dynrela->src);
                size = 4;
                break;
            default:
                sd_warn("unsupported rela type %ld for source %s (0x%lx <- 0x%lx)",
                       dynrela->type, dynrela->name, dynrela->dest,
                       dynrela->src);
                continue;
        }

        if (loc < core_start || loc >= core_start + core_size) {
            sd_err("bad dynrela location 0x%llx for symbol %s",
                    loc, dynrela->name);
            return -1;
        }

        memcpy((void *)loc, &val, size);
    }

    return 0;
}

static int lp_enable(struct livepatch_patch *new_patch,
                     struct livepatch_patch *old_patch, bool replace)
{
    int ret;
    struct livepatch_func *func, *failed;

    ret = write_relocations(new_patch);
    if (ret) {
        sd_err("write relocations for patch %s failed",
               new_patch->file->name);
        return ret;
    }

    suspend_worker_threads();
    if (replace) {
        /* unpatch old functions */
        list_for_each_entry(func, &old_patch->funcs, list) {
            replace_call(func->old_addr, (unsigned long)__fentry__);
            unregister_patched_func(func);
        }
    }

    /* patch new functions */
    list_for_each_entry(func, &new_patch->funcs, list) {
        ret = verify_symbol(func->name, func->old_addr);
        if (ret) {
            sd_err("symbol %s mismatch", func->name);
            failed = func;
            goto rollback;
        }

        if (make_text_available((void*)func->old_addr, INSN_SIZE) < 0) {
            sd_err("failed to make function (%s) replacable", func->name);
            failed = func;
            goto rollback;
        }

        register_patched_func(func);

        replace_call(func->old_addr, (unsigned long)livepatch_caller);
    }

    if (replace) {
        list_del(&old_patch->list);
        lp_unload(old_patch);
    }

out:
    resume_worker_threads();
    return ret;

rollback:
    /* resume old patch status */
    list_for_each_entry(func, &new_patch->funcs, list) {
        if (func == failed)
            break;
        replace_call(func->old_addr, (unsigned long)__fentry__);
        unregister_patched_func(func);
    }
    if (replace) {
        list_for_each_entry(func, &old_patch->funcs, list) {
            replace_call(func->old_addr, (unsigned long)livepatch_caller);
            register_patched_func(func);
        }
    }
    goto out;
}

static void lp_disable(struct livepatch_patch *patch)
{
    struct livepatch_func *func;

    suspend_worker_threads();
    list_for_each_entry(func, &patch->funcs, list) {
        replace_call(func->old_addr, (unsigned long)__fentry__);
        unregister_patched_func(func);
    }
    resume_worker_threads();
}

static struct livepatch_patch *check_patch_overlap(struct livepatch_patch *patch)
{
    struct livepatch_patch *old_patch;
    struct livepatch_func *old_func, *func;

    list_for_each_entry(old_patch, &patch_list, list) {
        /* don't check overlap for replace case */
        if (!strcmp(old_patch->file->name, patch->file->name))
            continue;

        list_for_each_entry(old_func, &old_patch->funcs, list) {
            list_for_each_entry(func, &patch->funcs, list) {
                if (func->old_addr == old_func->old_addr)
                    return old_patch;
            }
        }
    }

    return NULL;
}

int livepatch_patch(const char *patchname)
{
    int ret;
    struct livepatch_patch *new_patch, *old_patch, *overlap;
    int replace = 0;

    list_for_each_entry(old_patch, &patch_list, list) {
        if (!strcmp(old_patch->file->name, patchname)) {
            replace = 1;
            break;
        }
    }

    if (replace)
        sd_info("replacing already exist patch %s", patchname);

    new_patch = lp_load(patchname);
    if (!new_patch) {
        sd_err("failed to load patch %s", patchname);
        return SD_RES_SYSTEM_ERROR;
    }

    overlap = check_patch_overlap(new_patch);
    if (overlap) {
        sd_err("detect patch overlap %s v.s. %s",
                patchname, overlap->file->name);
        return SD_RES_SYSTEM_ERROR;
    }

    ret = lp_enable(new_patch, old_patch, replace);
    if (ret) {
        sd_err("failed to enable patch %s", patchname);
        lp_unload(new_patch);
        return SD_RES_SYSTEM_ERROR;
    }

    list_add_tail(&new_patch->list, &patch_list);

    return SD_RES_SUCCESS;
}

int livepatch_unpatch(const char *patchname)
{
    struct livepatch_patch *patch;
    int found = 0;

    list_for_each_entry(patch, &patch_list, list) {
        if (!strcmp(patch->file->name, patchname)) {
            list_del(&patch->list);
            found = 1;
            break;
        }
    }

    if (!found) {
        sd_err("no such patch (%s) found", patchname);
        return SD_RES_INVALID_PARMS;
    }

    lp_disable(patch);
    lp_unload(patch);

    return SD_RES_SUCCESS;
}

/**
 * format:
 *      patch1    [func1,func2]
 *      patch2    [func1,...]
 *      ...
 */
size_t livepatch_status(char *buf)
{
    struct livepatch_patch *patch;
    struct livepatch_func *func;
    char *p = buf;

    list_for_each_entry(patch, &patch_list, list) {
        strcpy(p, patch->file->name);
        p += strlen(patch->file->name);

        *p++ = '\t';
        *p++ = '[';
        list_for_each_entry(func, &patch->funcs, list) {
            strcpy(p, func->name);
            p += strlen(func->name);
            *p++ = ',';
        }
        /* overwrite tailing ',' */
        *(p - 1) = ']';
        *p++ = '\n';
    }

    *p++ = '\0';

    return p - buf;
}

static int init_patch_path(const char *base_path)
{
#define PATCH_PATH "/patch/"
	int len = strlen(base_path) + strlen(PATCH_PATH) + 1;
	patch_path = xzalloc(len);

	snprintf(patch_path, len, "%s" PATCH_PATH, base_path);

	return xmkdir(patch_path, sd_def_dmode);
}

static void init_patch_func_table(void)
{
    patched_func_table = xzalloc(sizeof(struct hlist_head) * PATCH_HASH_SIZE);
    for (unsigned int i = 0; i < PATCH_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(patched_func_table + i);
    }
}

static int init_lookup_table(void)
{
    exe_path = my_exe_path();
    table = lookup_open(exe_path);
    if (!table)
        return -1;
    return 0;
}

int livepatch_init(const char *base_path)
{
    int ret = 0;

    ret = init_patch_path(base_path);
    if (ret) {
        free(patch_path);
        return ret;
    }

    init_patch_func_table();

    ret = init_lookup_table();

    return ret;
}
