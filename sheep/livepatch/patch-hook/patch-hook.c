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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "list.h"
#include "logger.h"
#include "livepatch.h"
#include "livepatch-patch.h"

extern struct livepatch_patch_func __livepatch_funcs[], __livepatch_funcs_end[];
extern struct livepatch_patch_dynrela __livepatch_dynrelas[], __livepatch_dynrelas_end[];

int lp_init(void);
void lp_exit(void);

struct livepatch_patch __patch
__attribute__((section(".lp_patch_struct")));

static struct livepatch_patch *patch = &__patch;

struct livepatch_initexit initexit
__attribute__((section(".lp_initexit"))) = {
    .init = lp_init,
    .exit = lp_exit,
};

static void patch_init(void)
{
    INIT_LIST_HEAD(&patch->funcs);
    INIT_LIST_HEAD(&patch->dynrelas);
    INIT_LIST_NODE(&patch->list);
}

static void patch_free(void)
{
    struct livepatch_func *func;
    struct livepatch_dynrela *dynrela;

    list_for_each_entry(func, &patch->funcs, list) {
        list_del(&func->list);
        free(func);
    }

    list_for_each_entry(dynrela, &patch->dynrelas, list) {
        list_del(&dynrela->list);
        free(dynrela);
    }
}

static int patch_make_funcs_list(struct list_head *funcs)
{
	struct livepatch_patch_func *p_func;
	struct livepatch_func *func;

    sd_debug("make patched functions list");

	for (p_func = __livepatch_funcs; p_func < __livepatch_funcs_end; p_func++) {
		func = calloc(1, sizeof(*func));
		if (!func)
			return -ENOMEM;

		func->new_addr = p_func->new_addr;
		func->new_size = p_func->new_size;
        func->old_addr = p_func->old_addr;
		func->old_size = p_func->old_size;
		func->name = p_func->name;
		list_add_tail(&func->list, funcs);
	}

	return 0;
}

static int patch_make_dynrelas_list(struct list_head *dynrelas)
{
	struct livepatch_patch_dynrela *p_dynrela;
	struct livepatch_dynrela *dynrela;

    sd_debug("make patched functions dynrelas list");

	for (p_dynrela = __livepatch_dynrelas; p_dynrela < __livepatch_dynrelas_end;
	     p_dynrela++) {
		dynrela = calloc(1, sizeof(*dynrela));
		if (!dynrela)
			return -ENOMEM;

        dynrela->dest = p_dynrela->dest;
		dynrela->src = p_dynrela->src;
		dynrela->type = p_dynrela->type;
		dynrela->name = p_dynrela->name;
		dynrela->addend = p_dynrela->addend;
		list_add_tail(&dynrela->list, dynrelas);
	}

	return 0;
}

int __init lp_init(void)
{
    int ret;

    patch_init();

	ret = patch_make_funcs_list(&patch->funcs);
	if (ret)
        return ret;

	ret = patch_make_dynrelas_list(&patch->dynrelas);
	if (ret)
        return ret;

	return ret;
}

void __exit lp_exit(void)
{
    patch_free();
    return;
}
