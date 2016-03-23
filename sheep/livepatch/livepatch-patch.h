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

#ifndef _LIVEPATCH_PATCH_H_
#define _LIVEPATCH_PATCH_H_

struct livepatch_patch_func {
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
	char *name;
};

struct livepatch_patch_dynrela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
	char *name;
	int addend;
};

#endif /* _LIVEPATCH_PATCH_H_ */
