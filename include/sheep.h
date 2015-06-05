/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 * Copyright (C) 2012-2013 Taobao Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __SHEEP_H__
#define __SHEEP_H__

#include <stdint.h>
#include "internal_proto.h"
#include "logger.h"
#include "util.h"
#include "bitops.h"
#include "list.h"
#include "net.h"
#include "rbtree.h"

struct sd_vnode {
	struct rb_node rb;
	const struct sd_node *node;
	uint64_t hash;
};

struct vnode_info {
	struct rb_root vroot;
	struct rb_root nroot;
	int nr_nodes;
	int nr_zones;
	refcnt_t refcnt;
};

static inline void sd_init_req(struct sd_req *req, uint8_t opcode)
{
	memset(req, 0, sizeof(*req));
	req->opcode = opcode;
	req->proto_ver = opcode < 0x80 ? SD_PROTO_VER : SD_SHEEP_PROTO_VER;
}

static inline int same_zone(const struct sd_vnode *v1,
			    const struct sd_vnode *v2)
{
	return v1->node->zone == v2->node->zone;
}

static inline int vnode_cmp(const struct sd_vnode *node1,
			    const struct sd_vnode *node2)
{
	return intcmp(node1->hash, node2->hash);
}

/* If v1_hash < oid_hash <= v2_hash, then oid is resident on v2 */
static inline struct sd_vnode *
oid_to_first_vnode(uint64_t oid, struct rb_root *root)
{
	struct sd_vnode dummy = {
		.hash = sd_hash_oid(oid),
	};
	return rb_nsearch(root, &dummy, rb, vnode_cmp);
}

/* Replica are placed along the ring one by one with different zones */
static inline void oid_to_vnodes(uint64_t oid, struct rb_root *root,
				 int nr_copies,
				 const struct sd_vnode **vnodes)
{
	const struct sd_vnode *next = oid_to_first_vnode(oid, root);

	vnodes[0] = next;
	for (int i = 1; i < nr_copies; i++) {
next:
		next = rb_entry(rb_next(&next->rb), struct sd_vnode, rb);
		if (!next) /* Wrap around */
			next = rb_entry(rb_first(root), struct sd_vnode, rb);
		if (unlikely(next == vnodes[0]))
			panic("can't find a valid vnode");
		for (int j = 0; j < i; j++)
			if (same_zone(vnodes[j], next))
				goto next;
		vnodes[i] = next;
	}
}

static inline const struct sd_vnode *
oid_to_vnode(uint64_t oid, struct rb_root *root, int copy_idx)
{
	const struct sd_vnode *vnodes[SD_MAX_COPIES];

	oid_to_vnodes(oid, root, copy_idx + 1, vnodes);

	return vnodes[copy_idx];
}

static inline const struct sd_node *
oid_to_node(uint64_t oid, struct rb_root *root, int copy_idx)
{
	const struct sd_vnode *vnode;

	vnode = oid_to_vnode(oid, root, copy_idx);

	return vnode->node;
}

static inline void oid_to_nodes(uint64_t oid, struct rb_root *root,
				int nr_copies,
				const struct sd_node **nodes)
{
	const struct sd_vnode *vnodes[SD_MAX_COPIES];

	oid_to_vnodes(oid, root, nr_copies, vnodes);
	for (int i = 0; i < nr_copies; i++)
		nodes[i] = vnodes[i]->node;
}

static inline int oid_cmp(const uint64_t *oid1, const uint64_t *oid2)
{
	return intcmp(*oid1, *oid2);
}

static inline int node_id_cmp(const struct node_id *node1,
			      const struct node_id *node2)
{
	int cmp = memcmp(node1->addr, node2->addr, sizeof(node1->addr));
	if (cmp != 0)
		return cmp;

	return intcmp(node1->port, node2->port);
}

static inline int node_cmp(const struct sd_node *node1,
			   const struct sd_node *node2)
{
	return node_id_cmp(&node1->nid, &node2->nid);
}

static inline int oid_entry_cmp(const struct oid_entry *entry1,
			   const struct oid_entry *entry2)
{
	return node_cmp(entry1->node, entry2->node);
}

static inline bool node_eq(const struct sd_node *a, const struct sd_node *b)
{
	return node_cmp(a, b) == 0;
}

static inline uint64_t
node_disk_to_vnodes(const struct sd_node *n, struct rb_root *vroot)
{

	uint64_t node_hval = sd_hash(&n->nid, offsetof(typeof(n->nid),
						       io_addr));
	uint64_t hval, disk_vnodes, total = 0;

	for (int j = 0; j < DISK_MAX; j++) {
		if (!n->disks[j].disk_id)
			continue;
		hval = fnv_64a_64(node_hval, n->disks[j].disk_id);
		disk_vnodes = DIV_ROUND_UP(n->disks[j].disk_space, WEIGHT_MIN);
		total += disk_vnodes;
		for (int k = 0; k < disk_vnodes; k++) {
			hval = sd_hash_next(hval);
			struct sd_vnode *v = xmalloc(sizeof(*v));
			v->hash = hval;
			v->node = n;
			if (unlikely(rb_insert(vroot, v, rb, vnode_cmp)))
				panic("vdisk hash collison");
		}
	}
	return total;
}

static inline void
disks_to_vnodes(struct rb_root *nroot, struct rb_root *vroot)
{
	struct sd_node *n;

	rb_for_each_entry(n, nroot, rb)
		n->nr_vnodes = node_disk_to_vnodes(n, vroot);
}

static inline void
node_to_vnodes(const struct sd_node *n, struct rb_root *vroot)
{
	uint64_t hval = sd_hash(&n->nid, offsetof(typeof(n->nid),
						  io_addr));

	for (int i = 0; i < n->nr_vnodes; i++) {
		struct sd_vnode *v = xmalloc(sizeof(*v));

		hval = sd_hash_next(hval);
		v->hash = hval;
		v->node = n;
		if (unlikely(rb_insert(vroot, v, rb, vnode_cmp)))
			panic("vdisk hash collison");
	}
}

static inline void
nodes_to_vnodes(struct rb_root *nroot, struct rb_root *vroot)
{
	struct sd_node *n;

	rb_for_each_entry(n, nroot, rb)
		node_to_vnodes(n, vroot);
}

static inline void nodes_to_buffer(struct rb_root *nroot, void *buffer)
{
	struct sd_node *n, *buf = buffer;

	rb_for_each_entry(n, nroot, rb) {
		memcpy(buf++, n, sizeof(*n));
	}
}

#define MAX_NODE_STR_LEN 256

static inline const char *node_id_to_str(const struct node_id *id)
{
	static __thread char str[MAX_NODE_STR_LEN];
	int af = AF_INET6;
	const uint8_t *addr = id->addr;

	/* Find address family type */
	if (addr[12]) {
		int  oct_no = 0;
		while (!addr[oct_no] && oct_no++ < 12)
			;
		if (oct_no == 12)
			af = AF_INET;
	}

	snprintf(str, sizeof(str), "%s ip:%s port:%d",
		(af == AF_INET) ? "IPv4" : "IPv6",
		addr_to_str(id->addr, 0), id->port);

	return str;
}

static inline const char *node_to_str(const struct sd_node *id)
{
	return node_id_to_str(&id->nid);
}

static inline struct sd_node *str_to_node(const char *str, struct sd_node *id)
{
	int port;
	char v[8], ip[MAX_NODE_STR_LEN];

	sscanf(str, "%s ip:%s port:%d", v, ip, &port);
	id->nid.port = port;
	if (!str_to_addr(ip, id->nid.addr))
		return NULL;

	return id;
}

static inline bool is_cluster_diskmode(const struct cluster_info *cinfo)
{
	return (cinfo->flags & SD_CLUSTER_FLAG_DISKMODE) > 0;
}

static inline size_t count_data_objs(const struct sd_inode *inode)
{
	return DIV_ROUND_UP(inode->vdi_size,
			    (1UL << inode->block_size_shift));
}

static inline __attribute__((used)) void __sd_proto_build_bug_ons(void)
{
	/* never called, only for checking BUILD_BUG_ON()s */
	BUILD_BUG_ON(sizeof(struct sd_req) != SD_REQ_SIZE);
	BUILD_BUG_ON(sizeof(struct sd_rsp) != SD_RSP_SIZE);
}

#endif
