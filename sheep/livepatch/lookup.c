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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <gelf.h>
#include <unistd.h>
#include <dlfcn.h>

#include "util.h"
#include "list.h"
#include "lookup.h"

struct symbol {
	unsigned long value;
	unsigned long size;
	char *name;
	int type, bind, skip;
};

struct lib {
    char *name;
    void *h;
    struct list_node list;
};

#define for_each_symbol(ndx, iter, table) \
	for (ndx = 0, iter = table->syms; ndx < table->nr; ndx++, iter++)

struct lookup_table *lookup_open(const char *path)
{
	Elf *elf;
	int fd, i, len;
	Elf_Scn *scn, *sscn, *dscn;
	GElf_Shdr sh, ssh, dsh;
	GElf_Sym sym;
    GElf_Dyn dyn;
	Elf_Data *data;
	char *name, *err;
	struct lookup_table *table;
	struct symbol *mysym;
    struct lib *mylib;
	size_t shstrndx;

	if ((fd = open(path, O_RDONLY, 0)) < 0) {
        sd_err("failed to open file %s (%m)", path);
        return NULL;
    }

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
        sd_err("failed to elf_begin %s", path);
        goto out_close;
	}

	if (elf_getshdrstrndx(elf, &shstrndx)) {
		sd_err("failed to elf_getshdrstrndx");
        goto out_end;
    }

	scn = sscn = dscn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		if (!gelf_getshdr(scn, &sh)) {
			sd_err("failed to gelf_getshdr");
            goto out_end;
        }

		name = elf_strptr(elf, shstrndx, sh.sh_name);
		if (!name) {
			sd_err("failed to elf_strptr scn");
            goto out_end;
        }

		if (!strcmp(name, ".symtab"))
            sscn = scn;
        if (!strcmp(name, ".dynamic"))
            dscn = scn;
        if (sscn && dscn)
            break;
	}

	if (!sscn) {
		sd_err(".symtab section not found");
        goto out_end;
    }
    if (!dscn) {
        sd_err(".dynamic section not found");
        goto out_end;
    }

    if (!gelf_getshdr(sscn, &ssh)) {
        sd_err("failed to gelf_getshdr ssh");
        goto out_end;
    }
    if (!gelf_getshdr(dscn, &dsh)) {
        sd_err("failed to gelf_getshdr dsh");
        goto out_end;
    }

    /* setup symbol table */
	data = elf_getdata(sscn, NULL);
	if (!data) {
		sd_err("failed to elf_getdata");
        goto out_end;
    }

	len = ssh.sh_size / ssh.sh_entsize;

	table = xmalloc(sizeof(*table));
	table->syms = xzalloc(len * sizeof(struct symbol));
	table->nr = len;
	table->fd = fd;
	table->elf = elf;
    INIT_LIST_HEAD(&table->libs);

	for_each_symbol(i, mysym, table) {
		if (!gelf_getsym(data, i, &sym)) {
			sd_err("failed to gelf_getsym");
            goto out_free;
        }

		if (sym.st_shndx == SHN_UNDEF) {
			mysym->skip = 1;
			continue;
		}

		name = elf_strptr(elf, ssh.sh_link, sym.st_name);
		if(!name) {
			sd_err("failed to elf_strptr sym");
            goto out_free;
        }

		mysym->value = sym.st_value;
		mysym->size = sym.st_size;
		mysym->type = GELF_ST_TYPE(sym.st_info);
		mysym->bind = GELF_ST_BIND(sym.st_info);
		mysym->name = name;
	}

    /* setup library lookup table */
    data = elf_getdata(dscn, NULL);

    len = dsh.sh_size / dsh.sh_entsize;

    for (i = 0; i < len; i++) {
        if (!gelf_getdyn(data, i, &dyn)) {
            sd_err("failed to gelf_getdyn");
            goto out_free;
        }

        if (dyn.d_tag != DT_NEEDED)
            continue;

        name = elf_strptr(elf, dsh.sh_link, dyn.d_un.d_val);
        if (!name) {
            sd_err("failed to elf_strptr dyn");
            goto out_free;
        }
        mylib = xmalloc(sizeof(*mylib));
        mylib->name = name;
        mylib->h = dlopen(name, RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
        err = dlerror();
        if (err) {
            sd_err("dlopen failed (%s)", err);
            goto out_free;
        }
        list_add_tail(&mylib->list, &table->libs);
    }

	return table;

out_free:
    list_for_each_entry(mylib, &table->libs, list) {
        list_del(&mylib->list);
        free(mylib);
    }
    free(table->syms);
    free(table);
out_end:
    elf_end(elf);
out_close:
    close(fd);

    return NULL;
}

void lookup_close(struct lookup_table *table)
{
	elf_end(table->elf);
	close(table->fd);
	free(table);
}

int lookup_local_symbol(struct lookup_table *table, char *name, char *hint,
                        struct lookup_result *result)
{
	struct symbol *sym, *match = NULL;
	int i;
	char *curfile = NULL;

	memset(result, 0, sizeof(*result));
	for_each_symbol(i, sym, table) {
		if (sym->type == STT_FILE) {
			if (!strcmp(sym->name, hint)) {
				curfile = sym->name;
				continue; /* begin hint file symbols */
			} else if (curfile)
				curfile = NULL; /* end hint file symbols */
		}
		if (!curfile)
			continue;
		if (sym->bind == STB_LOCAL && !strcmp(sym->name, name)) {
			if (match)
				/* dup file+symbol, unresolvable ambiguity */
				return 1;
			match = sym;
		}
	}

	if (!match)
		return 1;

	result->value = match->value;
	result->size = match->size;
	return 0;
}

int lookup_global_symbol(struct lookup_table *table, char *name,
                         struct lookup_result *result)
{
	struct symbol *sym;
    struct lib *lib;
    void *addr;
	int i;

	memset(result, 0, sizeof(*result));
	for_each_symbol(i, sym, table)
		if (!sym->skip && (sym->bind == STB_GLOBAL || sym->bind == STB_WEAK) &&
		    !strcmp(sym->name, name)) {
			result->value = sym->value;
			result->size = sym->size;
			return 0;
		}

    list_for_each_entry(lib, &table->libs, list) {
        addr = dlsym(lib->h, name);
        if (!addr)
            continue;

        result->value = (unsigned long)addr;
        result->size = 0;
        return 0;
    }

	return 1;
}

int lookup_exist_symbol(struct lookup_table *table, char *name,
                        unsigned long addr)
{
	struct symbol *sym;
	int i;

	for_each_symbol(i, sym, table)
		if (!sym->skip && !strcmp(sym->name, name)) {
            if (addr == sym->value)
                return 0;
		}

	return 1;
}
