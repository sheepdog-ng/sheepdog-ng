/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Levin Li <xingke.lwp@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"

struct objlist_cache_entry {
	uint64_t oid;
	struct rb_node node;
};

struct objlist_cache {
	int tree_version;
	int buf_version;
	int cache_size;
	uint64_t *buf;
	struct rb_root root;
	struct sd_rw_lock lock;
};

struct objlist_migrate_cache {
	struct rb_root root;
	struct sd_rw_lock lock;
};

static struct objlist_cache obj_list_cache = {
	.tree_version	= 1,
	.root		= RB_ROOT,
	.lock		= SD_RW_LOCK_INITIALIZER,
};

static struct objlist_migrate_cache migrate_cache = {
	.root		= RB_ROOT,
	.lock		= SD_RW_LOCK_INITIALIZER,
};

static int objlist_cache_cmp(const struct objlist_cache_entry *a,
			     const struct objlist_cache_entry *b)
{
	return intcmp(a->oid, b->oid);
}

static struct objlist_cache_entry *objlist_cache_rb_insert(struct rb_root *root,
		struct objlist_cache_entry *new)
{
	return rb_insert(root, new, node, objlist_cache_cmp);
}

static int objlist_cache_rb_remove(struct rb_root *root, uint64_t oid)
{
	struct objlist_cache_entry *entry,  key = { .oid = oid  };

	entry = rb_search(root, &key, node, objlist_cache_cmp);
	if (!entry)
		return -1;

	rb_erase(&entry->node, root);
	free(entry);

	return 0;
}

void objlist_cache_remove(uint64_t oid)
{
	sd_write_lock(&obj_list_cache.lock);
	if (!objlist_cache_rb_remove(&obj_list_cache.root, oid)) {
		obj_list_cache.cache_size--;
		obj_list_cache.tree_version++;
	}
	sd_rw_unlock(&obj_list_cache.lock);
}

int objlist_cache_insert(uint64_t oid)
{
	struct objlist_cache_entry *entry, *p;

	entry = xzalloc(sizeof(*entry));
	entry->oid = oid;
	rb_init_node(&entry->node);

	sd_write_lock(&obj_list_cache.lock);
	p = objlist_cache_rb_insert(&obj_list_cache.root, entry);
	if (p)
		free(entry);
	else {
		obj_list_cache.cache_size++;
		obj_list_cache.tree_version++;
	}
	sd_rw_unlock(&obj_list_cache.lock);

	return 0;
}

int objlist_migrate_cache_insert(uint64_t oid)
{
	struct objlist_cache_entry *entry, *p;

	entry = xmalloc(sizeof(*entry));
	entry->oid = oid;
	rb_init_node(&entry->node);

	sd_write_lock(&migrate_cache.lock);
	p = objlist_cache_rb_insert(&migrate_cache.root, entry);
	if (p)
		free(entry);
	sd_rw_unlock(&migrate_cache.lock);

	return 0;
}

/*
 * oid might migrate from one node to the other during recovery, but we can't
 * simply remove it from objlist cache once it is being migrated because oid
 * would be lost at the stage of preparation of object list if no node get this
 * oid in its list. Because of this, we face a stale oid problem:
 *   if oid is being deleted in recovery and we can't remove it from list cache
 *   as mentioned above, some node might have this oid in its list cache, thus
 *   later recovery will try to recover non-existing oid.
 *
 *   1.
 *      oid migrate
 *   A -------------> B
 *      now request remove(oid) is blocked and wait for oid recovery completion.
 *   2.
 *   both A and B has oid in the list cache
 *   3
 *   the remove request will only go to B, not A after being waked up.
 *   4
 *   So A still has oid in its list and later recvoery will fail on this oid.
 *
 *   That said, we need to remove this kind of mismatched oid. The good timing
 *   to call this function is when all the nodes finish the recovery.
 */
void objlist_migrate_cache_retire(void)
{
	struct objlist_cache_entry *entry;
	struct vnode_info *vinfo = get_vnode_info();

	rb_for_each_entry(entry, &migrate_cache.root, node) {
		uint64_t oid = entry->oid;
		/* For some reason, oid gets back during multiple node events */
		if (is_erasure_oid(oid)) {
			uint8_t idx = local_ec_index(vinfo, oid);
			if (idx != SD_MAX_COPIES)
				continue;
		} else {
			if (sd_store->exist(oid, SD_MAX_COPIES))
				continue;
		}
		sd_debug("%"PRIx64, oid);
		objlist_cache_remove(oid);
	}
	put_vnode_info(vinfo);
	rb_destroy(&migrate_cache.root, struct objlist_cache_entry, node);
}

int get_obj_list(const struct sd_req *hdr, struct sd_rsp *rsp, void *data)
{
	int nr = 0;
	struct objlist_cache_entry *entry;

	/* first try getting the cached buffer with only a read lock held */
	sd_read_lock(&obj_list_cache.lock);
	if (obj_list_cache.tree_version == obj_list_cache.buf_version)
		goto out;

	/* if that fails grab a write lock for the usually necessary update */
	sd_rw_unlock(&obj_list_cache.lock);
	sd_write_lock(&obj_list_cache.lock);
	if (obj_list_cache.tree_version == obj_list_cache.buf_version)
		goto out;

	obj_list_cache.buf_version = obj_list_cache.tree_version;
	obj_list_cache.buf = xrealloc(obj_list_cache.buf,
				obj_list_cache.cache_size * sizeof(uint64_t));

	rb_for_each_entry(entry, &obj_list_cache.root, node) {
		obj_list_cache.buf[nr++] = entry->oid;
	}

out:
	if (hdr->data_length < obj_list_cache.cache_size * sizeof(uint64_t)) {
		sd_rw_unlock(&obj_list_cache.lock);
		sd_debug("GET_OBJ_LIST buffer too small");
		return SD_RES_BUFFER_SMALL;
	}

	rsp->data_length = obj_list_cache.cache_size * sizeof(uint64_t);
	memcpy(data, obj_list_cache.buf, rsp->data_length);
	sd_rw_unlock(&obj_list_cache.lock);
	return SD_RES_SUCCESS;
}

void objlist_cache_format(void)
{
	sd_write_lock(&obj_list_cache.lock);
	rb_destroy(&obj_list_cache.root, struct objlist_cache_entry, node);
	INIT_RB_ROOT(&obj_list_cache.root);
	obj_list_cache.tree_version = 1;
	obj_list_cache.buf_version = 0;
	if (NULL != obj_list_cache.buf) {
		free(obj_list_cache.buf);
		obj_list_cache.buf = NULL;
	}
	obj_list_cache.cache_size = 0;
	sd_rw_unlock(&obj_list_cache.lock);

	sd_write_lock(&migrate_cache.lock);
	rb_destroy(&migrate_cache.root, struct objlist_cache_entry, node);
	INIT_RB_ROOT(&migrate_cache.root);
	sd_rw_unlock(&migrate_cache.lock);
}
