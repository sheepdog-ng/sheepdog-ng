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

#ifndef _LIVEPATCH_LOOKUP_H_
#define _LIVEPATCH_LOOKUP_H_

#include <gelf.h>

struct lookup_table {
	int fd, nr;
	Elf *elf;
	struct symbol *syms;
    /* library handles list */
    struct list_head libs;
};


struct lookup_result {
	unsigned long value;
	unsigned long size;
};

struct lookup_table *lookup_open(const char *path);
void lookup_close(struct lookup_table *table);
int lookup_local_symbol(struct lookup_table *table, char *name, char *hint,
                        struct lookup_result *result);
int lookup_global_symbol(struct lookup_table *table, char *name,
                         struct lookup_result *result);
int lookup_exist_symbol(struct lookup_table *table, char *name,
                        unsigned long addr);

#endif /* _LIVEPATCH_LOOKUP_H_ */
