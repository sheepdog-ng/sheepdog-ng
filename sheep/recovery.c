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

#include "sheep_priv.h"

/* base structure for the recovery thread */
struct recovery_work {
	uint32_t epoch;
	uint32_t tgt_epoch;

	struct recovery_info *rinfo;
	struct vnode_info *old_vinfo;
	struct vnode_info *cur_vinfo;

	struct work work;
};

/* for preparing lists */
struct recovery_list_work {
	struct recovery_work base;

	uint64_t count;
	uint64_t *oids;
};

/* for recovering objects */
struct recovery_obj_work {
	struct recovery_work base;

	uint64_t oid; /* the object to be recovered */
	bool stop;
};

/*
 * recovery information
 *
 * We cannot access the members of this structure outside of the main thread.
 */
struct recovery_info {
	enum rw_state state;

	uint32_t epoch;
	uint32_t tgt_epoch;
	uint64_t done;
	uint64_t next;

	bool notify_complete;

	uint64_t count;
	uint64_t *oids;
	uint64_t *prio_oids;
	uint64_t nr_prio_oids;
	uint64_t nr_scheduled_prio_oids;

	struct vnode_info *old_vinfo;
	struct vnode_info *cur_vinfo;

	int max_epoch;
	struct vnode_info **vinfo_array;
	struct sd_mutex vinfo_lock;

	uint32_t recover_threads;
};

static struct recovery_info *next_rinfo;
static main_thread(struct recovery_info *) current_rinfo;

static void queue_recovery_work(struct recovery_info *rinfo);

/* Dynamically grown list buffer default as 4M (2T storage) */
#define DEFAULT_LIST_BUFFER_SIZE (UINT64_C(1) << 22)
static size_t list_buffer_size = DEFAULT_LIST_BUFFER_SIZE;

static int obj_cmp(const uint64_t *oid1, const uint64_t *oid2)
{
	return intcmp(*oid1, *oid2);
}

static inline bool node_is_gateway_only(void)
{
	return sys->this_node.nr_vnodes == 0;
}

static struct vnode_info *rollback_vnode_info(uint32_t *epoch,
					      struct recovery_info *rinfo,
					      struct vnode_info *cur)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;
	struct rb_root nroot = RB_ROOT;

rollback:
	*epoch -= 1;
	if (!*epoch)
		return NULL;

	nr_nodes = get_nodes_epoch(*epoch, cur, nodes, sizeof(nodes));
	if (!nr_nodes) {
		/* We rollback in case we don't get a valid epoch */
		sd_alert("cannot get epoch %d", *epoch);
		sd_alert("clients may see old data");

		goto rollback;
	}
	/* double check */
	if (rinfo->vinfo_array[*epoch] == NULL) {
		sd_mutex_lock(&rinfo->vinfo_lock);
		if (rinfo->vinfo_array[*epoch] == NULL) {
			for (int i = 0; i < nr_nodes; i++)
				rb_insert(&nroot, &nodes[i], rb, node_cmp);
			rinfo->vinfo_array[*epoch] = alloc_vnode_info(&nroot);
		}
		sd_mutex_unlock(&rinfo->vinfo_lock);
	}
	grab_vnode_info(rinfo->vinfo_array[*epoch]);
	return rinfo->vinfo_array[*epoch];
}

/*
 * A node that does not match any node in current node list means the node has
 * left the cluster, then it's an invalid node.
 */
static bool invalid_node(const struct sd_node *n, struct vnode_info *info)
{

	if (rb_search(&info->nroot, n, rb, node_cmp))
		return false;
	return true;
}

static int search_erasure_object(uint64_t oid, uint8_t idx,
				 struct rb_root *nroot,
				 struct recovery_work *rw,
				 uint32_t tgt_epoch,
				 void *buf)
{
	struct sd_req hdr;
	unsigned rlen = get_store_objsize(oid);
	struct sd_node *n;
	uint32_t epoch = rw->epoch;

	rb_for_each_entry(n, nroot, rb) {
		if (invalid_node(n, rw->cur_vinfo))
			continue;
		sd_init_req(&hdr, SD_OP_READ_PEER);
		hdr.epoch = epoch;
		hdr.flags = SD_FLAG_CMD_RECOVERY;
		hdr.data_length = rlen;
		hdr.obj.oid = oid;
		hdr.obj.tgt_epoch = tgt_epoch;
		hdr.obj.ec_index = idx;

		sd_debug("%"PRIx64" epoch %"PRIu32" tgt %"PRIu32" idx %d, %s",
			 oid, epoch, tgt_epoch, idx, node_to_str(n));
		if (sheep_exec_req(&n->nid, &hdr, buf) == SD_RES_SUCCESS)
			return SD_RES_SUCCESS;
	}
	return SD_RES_NO_OBJ;
}

static void *read_erasure_object(uint64_t oid, uint8_t idx,
				 struct recovery_obj_work *row)
{
	struct sd_req hdr;
	unsigned rlen = get_store_objsize(oid);
	void *buf = xvalloc(rlen);
	struct recovery_work *rw = &row->base;
	struct vnode_info *old = grab_vnode_info(rw->old_vinfo), *new_old;
	uint32_t epoch = rw->epoch, tgt_epoch = rw->tgt_epoch;
	const struct sd_node *node;
	uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
	int edp = ec_policy_to_dp(policy, NULL, NULL);
	int ret;
again:
	if (unlikely(old->nr_zones < edp)) {
		if (search_erasure_object(oid, idx, &old->nroot, rw,
					  tgt_epoch, buf)
		    == SD_RES_SUCCESS)
			goto done;
		else
			goto rollback;
	}
	node = oid_to_node(oid, &old->vroot, idx);
	sd_debug("%"PRIx64" epoch %"PRIu32" tgt %"PRIu32" idx %d, %s",
		 oid, epoch, tgt_epoch, idx, node_to_str(node));
	if (invalid_node(node, rw->cur_vinfo))
		goto rollback;
	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY;
	hdr.data_length = rlen;
	hdr.obj.oid = oid;
	hdr.obj.tgt_epoch = tgt_epoch;
	hdr.obj.ec_index = idx;

	ret = sheep_exec_req(&node->nid, &hdr, buf);
	switch (ret) {
	case SD_RES_SUCCESS:
		goto done;
	case SD_RES_OLD_NODE_VER:
		free(buf);
		buf = NULL;
		row->stop = true;
		break;
	default:
rollback:
		new_old = rollback_vnode_info(&tgt_epoch, rw->rinfo,
					      rw->cur_vinfo);
		if (!new_old) {
			sd_warn("can not read %"PRIx64" idx %d", oid, idx);
			free(buf);
			buf = NULL;
			goto done;
		}
		if (rb_identical(&new_old->vroot, struct sd_vnode, rb,
				 &old->vroot, vnode_cmp)) {
			sd_debug("skip the identical epoch %"PRIu32, tgt_epoch);
			put_vnode_info(new_old);
			goto rollback;
		}
		put_vnode_info(old);
		old = new_old;
		goto again;
	}
done:
	put_vnode_info(old);
	return buf;
}

/*
 * Read object from targeted node and store it in the local node.
 *
 * tgt_epoch: the specific epoch that the object has stayed
 * idx: erasure index. For non-erasure object, pass 0.
 */
static int recover_object_from(struct recovery_obj_work *row,
			       const struct sd_node *node,
			       uint32_t tgt_epoch)
{
	uint64_t oid = row->oid;
	uint32_t epoch = row->base.epoch;
	int ret;
	unsigned rlen;
	void *buf = NULL;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct siocb iocb = { 0 };

	if (node_is_local(node)) {
		if (tgt_epoch < sys_epoch())
			return sd_store->link(oid, tgt_epoch);

		return SD_RES_NO_OBJ;
	}

	rlen = get_store_objsize(oid);
	buf = xvalloc(rlen);

	/* recover from remote replica */
	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY;
	hdr.data_length = rlen;
	hdr.obj.oid = oid;
	hdr.obj.tgt_epoch = tgt_epoch;

	ret = sheep_exec_req(&node->nid, &hdr, buf);
	if (ret == SD_RES_SUCCESS) {
		iocb.epoch = epoch;
		iocb.length = rsp->data_length;
		iocb.offset = rsp->obj.offset;
		iocb.buf = buf;
		ret = sd_store->create_and_write(oid, &iocb);
	}

	free(buf);
	return ret;
}

static int recover_object_from_replica(struct recovery_obj_work *row,
				       struct vnode_info *old,
				       uint32_t tgt_epoch)
{
	uint64_t oid = row->oid;
	uint32_t epoch = row->base.epoch;
	int nr_copies, ret = SD_RES_SUCCESS, start = 0;
	bool fully_replicated = true;

	nr_copies = get_obj_copy_number(oid, old->nr_zones);

	/* find local node first to try to recover from local */
	for (int i = 0; i < nr_copies; i++) {
		const struct sd_vnode *vnode;

		vnode = oid_to_vnode(oid, &old->vroot, i);

		if (vnode_is_local(vnode)) {
			start = i;
			break;
		}
	}

	/* Let's do a breadth-first search */
	for (int i = 0; i < nr_copies; i++) {
		const struct sd_node *node;
		int idx = (i + start) % nr_copies;

		node = oid_to_node(oid, &old->vroot, idx);

		if (invalid_node(node, row->base.cur_vinfo))
			continue;

		ret = recover_object_from(row, node, tgt_epoch);
		switch (ret) {
		case SD_RES_SUCCESS:
			sd_debug("recovered oid %"PRIx64" from %d to epoch %d",
				 oid, tgt_epoch, epoch);
			return ret;
		case SD_RES_OLD_NODE_VER:
			/* move to the next epoch recovery */
			return ret;
		case SD_RES_NO_OBJ:
			fully_replicated = false;
			/* fall through */
		default:
			break;
		}
	}

	/*
	 * sheep would return a stale object when
	 *  - all the nodes hold the copies, and
	 *  - all the nodes are gone
	 * at the some epoch
	 */
	if (fully_replicated && ret != SD_RES_SUCCESS)
		ret = SD_RES_STALE_OBJ;

	return ret;
}

/*
 * Recover the object from its track in epoch history. That is,
 * the routine will try to recovery it from the nodes it has stayed,
 * at least, *theoretically* on consistent hash ring.
 */
static int recover_replication_object(struct recovery_obj_work *row)
{
	struct recovery_work *rw = &row->base;
	struct vnode_info *old;
	uint64_t oid = row->oid;
	uint32_t tgt_epoch = rw->tgt_epoch;
	int ret;
	struct vnode_info *new_old;

	old = grab_vnode_info(rw->old_vinfo);
again:
	sd_debug("try recover object %"PRIx64" from epoch %"PRIu32, oid,
		 tgt_epoch);

	ret = recover_object_from_replica(row, old, tgt_epoch);

	switch (ret) {
	case SD_RES_SUCCESS:
		/* Succeed */
		break;
	case SD_RES_OLD_NODE_VER:
		row->stop = true;
		break;
	case SD_RES_NO_SPACE:
		break;
	case SD_RES_STALE_OBJ:
		sd_alert("cannot access any replicas of %"PRIx64" at epoch %d",
			 oid, tgt_epoch);
		sd_alert("clients may see old data");
		/* fall through */
	default:
rollback:
		/* No luck, roll back to an older configuration and try again */
		new_old = rollback_vnode_info(&tgt_epoch, rw->rinfo,
					      rw->cur_vinfo);
		if (!new_old) {
			sd_err("can not recover oid %"PRIx64, oid);
			ret = -1;
			goto out;
		}
		if (rb_identical(&new_old->vroot, struct sd_vnode, rb,
				 &old->vroot, vnode_cmp)) {
			sd_debug("skip the identical epoch %"PRIu32, tgt_epoch);
			put_vnode_info(new_old);
			goto rollback;
		}
		put_vnode_info(old);
		old = new_old;
		goto again;
	}
out:
	put_vnode_info(old);
	return ret;
}

static void *rebuild_erasure_object(uint64_t oid, uint8_t idx,
				    struct recovery_obj_work *row)
{
	int len = get_store_objsize(oid);
	char *lost = xvalloc(len);
	int i, j;
	uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
	int ed = 0, edp;
	edp = ec_policy_to_dp(policy, &ed, NULL);
	struct fec *ctx = ec_init(ed, edp);
	uint8_t *bufs[ed];
	int idxs[ed];

	for (i = 0; i < ed; i++) {
		bufs[i] = NULL;
		idxs[i] = 0;
	}

	/* Prepare replica */
	for (i = 0, j = 0; i < edp && j < ed; i++) {
		if (i == idx)
			continue;
		bufs[j] = read_erasure_object(oid, i, row);
		if (row->stop)
			break;
		if (!bufs[j])
			continue;
		idxs[j++] = i;
	}
	if (j != ed) {
		free(lost);
		lost = NULL;
		goto out;
	}

	/* Rebuild the lost replica */
	ec_decode_buffer(ctx, bufs, idxs, lost, idx);
out:
	ec_destroy(ctx);
	for (i = 0; i < ed; i++)
		free(bufs[i]);
	return lost;
}

uint8_t local_ec_index(struct vnode_info *vinfo, uint64_t oid)
{
	int idx, m = min(get_vdi_copy_number(oid_to_vid(oid)), vinfo->nr_zones);

	if (!is_erasure_oid(oid))
		return SD_MAX_COPIES;

	for (idx = 0; idx < m; idx++) {
		const struct sd_node *n = oid_to_node(oid, &vinfo->vroot, idx);
		if (node_is_local(n))
			return idx;
	}
	sd_debug("can't get valid index for %"PRIx64, oid);
	return SD_MAX_COPIES;
}

/*
 * Erasure object recovery algorithm
 *
 * 1. read the lost object from its track in epoch history vertically because
 *    every copy that holds partial data of the object is unique
 * 2. if not found in 1, then tries to rebuild it with RS algorithm
 *    2.1 read enough other copies from their tracks in epoch history
 *    2.2 rebuild the lost object from the content of copies read at 2.1
 *
 * The subtle case is number for available zones is less than total copy number
 * or the requested index of lost object:
 *    1 we need to make sure nr_zones >= total_copy_nr to avoid panic of
 *      oid_to_node(s) helpers.
 *    2 we have to search all the available zones when we can't get idx. Its
 *      okay to do a mad search when number of available zones is small
 */
static int recover_erasure_object(struct recovery_obj_work *row)
{
	struct recovery_work *rw = &row->base;
	struct vnode_info *cur = rw->cur_vinfo;
	uint64_t oid = row->oid;
	struct siocb iocb = { 0 };
	void *buf = NULL;
	uint8_t idx;
	int ret = -1;

	idx = local_ec_index(cur, oid);
	buf = read_erasure_object(oid, idx, row);
	if (!buf && !row->stop)
		buf = rebuild_erasure_object(oid, idx, row);
	if (!buf) {
		if (!row->stop)
			sd_err("failed to recover %"PRIx64" idx %d", oid, idx);
		goto out;
	}

	iocb.epoch = rw->epoch;
	iocb.length = get_store_objsize(oid);
	iocb.offset = 0;
	iocb.buf = buf;
	iocb.ec_index = idx;
	ret = sd_store->create_and_write(oid, &iocb);
	free(buf);
out:
	return ret;
}

static int do_recover_object(struct recovery_obj_work *row)
{
	uint64_t oid = row->oid;

	sd_debug("try recover object %"PRIx64, oid);

	if (is_erasure_oid(oid))
		return recover_erasure_object(row);
	else
		return recover_replication_object(row);
}

static void recover_object_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_obj_work *row = container_of(rw,
						     struct recovery_obj_work,
						     base);
	uint64_t oid = row->oid;
	struct vnode_info *cur = rw->cur_vinfo;
	int ret;

	if (sd_store->exist(oid, local_ec_index(cur, oid))) {
		sd_debug("the object is already recovered");
		return;
	}

	ret = do_recover_object(row);
	if (ret != 0)
		sd_err("failed to recover object %"PRIx64, oid);
}

bool node_in_recovery(void)
{
	return main_thread_get(current_rinfo) != NULL;
}

static inline void prepare_schedule_oid(uint64_t oid)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	if (xlfind(&oid, rinfo->prio_oids, rinfo->nr_prio_oids, oid_cmp)) {
		sd_debug("%" PRIx64 " has been already in prio_oids", oid);
		return;
	}

	rinfo->nr_prio_oids++;
	rinfo->prio_oids = xrealloc(rinfo->prio_oids,
				    rinfo->nr_prio_oids * sizeof(uint64_t));
	rinfo->prio_oids[rinfo->nr_prio_oids - 1] = oid;
	sd_debug("%"PRIx64" nr_prio_oids %"PRIu64, oid, rinfo->nr_prio_oids);
}

main_fn bool oid_in_recovery(uint64_t oid, uint8_t opcode)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);
	struct vnode_info *cur;

	if (!node_in_recovery())
		return false;

	cur = rinfo->cur_vinfo;
	/*
	 * For remove operatoin, we need to wait for object to recovered by
	 * recovery thread, otherwise later recovery thread will recver the
	 * object after it is removed.
	 */
	if ((opcode != SD_OP_REMOVE_OBJ && opcode != SD_OP_REMOVE_PEER) &&
	    sd_store->exist(oid, local_ec_index(cur, oid))) {
		sd_debug("the object %" PRIx64 " is already recovered", oid);
		return false;
	}

	if (uatomic_read(&next_rinfo))
		/*
		 * The current recovery_info will be taken over by the next one
		 * soon, so no need to call prepare_schedule_oid() now.
		 */
		return true;

	switch (rinfo->state) {
	case RW_PREPARE_LIST:
		/* oid is not recovered yet */
		break;
	case RW_RECOVER_OBJ:
		if (xlfind(&oid, rinfo->oids, rinfo->done, oid_cmp)) {
			sd_debug("%" PRIx64 " has been already recovered", oid);
			return false;
		}

		if (xlfind(&oid, rinfo->oids + rinfo->done,
			   rinfo->next - rinfo->done, oid_cmp)) {
			/*
			 * rinfo->oids[rinfo->done .. rinfo->next) is currently
			 * being recovered and no need to call
			 * prepare_schedule_oid().
			 */
			return true;
		}

		/*
		 * Check if oid is in the list that to be recovered later
		 *
		 * FIXME: do we need more efficient yet complex data structure?
		 */
		if (xlfind(&oid, rinfo->oids + rinfo->next,
			   rinfo->count - rinfo->next + 1, oid_cmp))
			break;

		/*
		 * Newly created object after prepare_object_list() might not be
		 * in the list
		 */
		sd_debug("%"PRIx64" is not in the recovery list", oid);
		return false;
	case RW_NOTIFY_COMPLETION:
		sd_debug("the object %" PRIx64 " is already recovered", oid);
		return false;
	}

	prepare_schedule_oid(oid);
	return true;
}

static void free_recovery_work(struct recovery_work *rw)
{
	put_vnode_info(rw->cur_vinfo);
	put_vnode_info(rw->old_vinfo);
	free(rw);
}

static void free_recovery_list_work(struct recovery_list_work *rlw)
{
	put_vnode_info(rlw->base.cur_vinfo);
	put_vnode_info(rlw->base.old_vinfo);
	free(rlw->oids);
	free(rlw);
}

static void free_recovery_obj_work(struct recovery_obj_work *row)
{
	put_vnode_info(row->base.cur_vinfo);
	put_vnode_info(row->base.old_vinfo);
	free(row);
}

static void free_recovery_info(struct recovery_info *rinfo)
{
	put_vnode_info(rinfo->cur_vinfo);
	put_vnode_info(rinfo->old_vinfo);
	free(rinfo->oids);
	free(rinfo->prio_oids);
	for (int i = 0; i < rinfo->max_epoch; i++)
		put_vnode_info(rinfo->vinfo_array[i]);
	free(rinfo->vinfo_array);
	sd_destroy_mutex(&rinfo->vinfo_lock);
	free(rinfo);
}

/* Return true if next recovery work is queued. */
static inline bool run_next_rw(void)
{
	struct recovery_info *nrinfo = uatomic_read(&next_rinfo);
	struct recovery_info *cur = main_thread_get(current_rinfo);

	if (nrinfo == NULL)
		return false;

	/* Some objects are still in recovery. */
	if (cur->recover_threads) {
		sd_debug("some threads still running, wait for completion");
		return true;
	}

	nrinfo = uatomic_xchg_ptr(&next_rinfo, NULL);
	/*
	 * When md recovery supersedes the reweight or node recovery, we need to
	 * notify completion.
	 */
	if (!nrinfo->notify_complete && cur->notify_complete)
		nrinfo->notify_complete = true;

	free_recovery_info(cur);

	if (!node_is_gateway_only()) {
		int ret;
		ret = sd_store->update_epoch(nrinfo->tgt_epoch);
		if (ret != SD_RES_SUCCESS)
			sd_err("failed to update epoch %"PRIu32 " %s",
			       nrinfo->tgt_epoch, sd_strerror(ret));
	}

	main_thread_set(current_rinfo, nrinfo);
	wakeup_all_requests();
	queue_recovery_work(nrinfo);
	sd_debug("recovery work is superseded");
	return true;
}

static void notify_recovery_completion_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct sd_req hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_COMPLETE_RECOVERY);
	hdr.obj.tgt_epoch = rw->epoch;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(sys->this_node);

	ret = exec_local_req(&hdr, &sys->this_node);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to notify recovery completion, %d", rw->epoch);
}

static void notify_recovery_completion_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	free_recovery_work(rw);
}

static inline void finish_recovery(struct recovery_info *rinfo)
{
	uint32_t recovered_epoch = rinfo->epoch;
	main_thread_set(current_rinfo, NULL);

	wakeup_all_requests();

	if (rinfo->notify_complete) {
		rinfo->state = RW_NOTIFY_COMPLETION;
		queue_recovery_work(rinfo);
	}

	free_recovery_info(rinfo);

	sd_debug("recovery complete: new epoch %"PRIu32, recovered_epoch);
}

static inline bool oid_in_prio_oids(struct recovery_info *rinfo, uint64_t oid)
{
	for (uint64_t i = 0; i < rinfo->nr_prio_oids; i++)
		if (rinfo->prio_oids[i] == oid)
			return true;
	return false;
}

/*
 * Schedule prio_oids to be recovered first in FIFO order
 *
 * rw->next is index of the original next object to be recovered and also the
 * number of objects already recovered and being recovered.
 * we just move rw->prio_oids in between:
 *   new_oids = [0..rw->next - 1] + [rw->prio_oids] + [rw->next]
 */
static inline void finish_schedule_oids(struct recovery_info *rinfo)
{
	uint64_t i, nr_recovered = rinfo->next, new_idx;
	uint64_t *new_oids;

	/* If I am the last oid, done */
	if (nr_recovered == rinfo->count - 1)
		goto done;

	new_oids = xmalloc(list_buffer_size);
	memcpy(new_oids, rinfo->oids, nr_recovered * sizeof(uint64_t));
	memcpy(new_oids + nr_recovered, rinfo->prio_oids,
	       rinfo->nr_prio_oids * sizeof(uint64_t));
	new_idx = nr_recovered + rinfo->nr_prio_oids;

	for (i = rinfo->next; i < rinfo->count; i++) {
		if (oid_in_prio_oids(rinfo, rinfo->oids[i]))
			continue;
		new_oids[new_idx++] = rinfo->oids[i];
	}
	/* rw->count should eq new_idx, otherwise something is wrong */
	sd_debug("%snr_recovered %" PRIu64 ", nr_prio_oids %" PRIu64 ", count %"
		 PRIu64 " = new %" PRIu64,
		 rinfo->count == new_idx ? "" : "WARN: ", nr_recovered,
		 rinfo->nr_prio_oids, rinfo->count, new_idx);

	free(rinfo->oids);
	rinfo->oids = new_oids;
done:
	free(rinfo->prio_oids);
	rinfo->prio_oids = NULL;
	rinfo->nr_scheduled_prio_oids += rinfo->nr_prio_oids;
	rinfo->nr_prio_oids = 0;
}

static void recover_next_object(struct recovery_info *rinfo)
{
	if (run_next_rw())
		return;

	if (rinfo->nr_prio_oids)
		finish_schedule_oids(rinfo);

	/* no more objects to be recovered */
	if (rinfo->next >= rinfo->count)
		return;

	/* Try recover next object */
	queue_recovery_work(rinfo);
	rinfo->next++;
	rinfo->recover_threads++;
}

static void recover_object_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_obj_work *row = container_of(rw,
						     struct recovery_obj_work,
						     base);
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	rinfo->recover_threads--;

	/* if recovery is stopped, there is no reason to mark it as recovered */
	if (row->stop == true)
		goto skip;

	/* ->oids[done, next] is out of order since finish order is random */
	if (rinfo->oids[rinfo->done] != row->oid) {
		uint64_t *p = xlfind(&row->oid, rinfo->oids + rinfo->done,
				     rinfo->next - rinfo->done, oid_cmp);

		*p = rinfo->oids[rinfo->done];
		rinfo->oids[rinfo->done] = row->oid;
	}
	rinfo->done++;

skip:
	if (run_next_rw()) {
		free_recovery_obj_work(row);
		return;
	}

	wakeup_requests_on_oid(row->oid);

	if (!(rinfo->done % DIV_ROUND_UP(rinfo->count, 100)))
		sd_info("object recovery progress %3.0lf%% ",
			(double)rinfo->done / rinfo->count * 100);
	sd_debug("object %"PRIx64" is recovered (%"PRIu64"/%"PRIu64")",
		row->oid, rinfo->done, rinfo->count);

	if (rinfo->done >= rinfo->count)
		goto finish_recovery;

	recover_next_object(rinfo);
	free_recovery_obj_work(row);
	return;
finish_recovery:
	finish_recovery(rinfo);
	free_recovery_obj_work(row);
}

static void finish_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_list_work *rlw = container_of(rw,
						      struct recovery_list_work,
						      base);
	struct recovery_info *rinfo = main_thread_get(current_rinfo);
	/*
	 * Rationale for multi-threaded recovery:
	 * 1. If one node is added, we find that all the VMs on other nodes will
	 *    get noticeably affected until 50% data is transferred to the new
	 *    node.
	 * 2. For node failure, we might not have problems of running VM but the
	 *    recovery process boost will benefit IO operation of VM with less
	 *    chances to be blocked for write and also improve reliability.
	 * 3. For disk failure in node, this is similar to adding a node. All
	 *    the data on the broken disk will be recovered on other disks in
	 *    this node. Speedy recovery not only improve data reliability but
	 *    also cause less writing blocking on the lost data.
	 *
	 * We choose md_nr_disks() * 2 threads for recovery, no rationale.
	 */
	uint32_t nr_threads = md_nr_disks() * 2;

	rinfo->state = RW_RECOVER_OBJ;
	rinfo->count = rlw->count;
	rinfo->oids = rlw->oids;
	rlw->oids = NULL;
	free_recovery_list_work(rlw);

	if (run_next_rw())
		return;

	if (!rinfo->count) {
		finish_recovery(rinfo);
		return;
	}

	for (uint32_t i = 0; i < nr_threads; i++)
		recover_next_object(rinfo);
	return;
}

/* Fetch the object list from all the nodes in the cluster */
static uint64_t *fetch_object_list(struct sd_node *e, uint32_t epoch,
				   size_t *nr_oids)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	size_t buf_size = list_buffer_size;
	uint64_t *buf = xmalloc(buf_size);
	int ret;

	sd_debug("%s", addr_to_str(e->nid.addr, e->nid.port));

retry:
	sd_init_req(&hdr, SD_OP_GET_OBJ_LIST);
	hdr.data_length = buf_size;
	hdr.epoch = epoch;
	ret = sheep_exec_req(&e->nid, &hdr, buf);

	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_BUFFER_SMALL:
		buf_size *= 2;
		buf = xrealloc(buf, buf_size);
		goto retry;
	default:
		sd_alert("cannot get object list from %s",
			 addr_to_str(e->nid.addr, e->nid.port));
		sd_alert("some objects may be not recovered at epoch %d",
			 epoch);
		free(buf);
		return NULL;
	}

	*nr_oids = rsp->data_length / sizeof(uint64_t);
	sd_debug("%zu", *nr_oids);
	return buf;
}

/* Screen out objects that don't belong to this node */
static void screen_object_list(struct recovery_list_work *rlw,
			       uint64_t *oids, size_t nr_oids)
{
	struct recovery_work *rw = &rlw->base;
	const struct sd_vnode *vnodes[SD_MAX_COPIES];
	uint64_t old_count = rlw->count;
	uint64_t nr_objs;
	uint64_t i, j;

	for (i = 0; i < nr_oids; i++) {
		if (xbsearch(&oids[i], rlw->oids, old_count, obj_cmp))
			/* the object is already scheduled to be recovered */
			continue;

		nr_objs = get_obj_copy_number(oids[i], rw->cur_vinfo->nr_zones);

		oid_to_vnodes(oids[i], &rw->cur_vinfo->vroot, nr_objs, vnodes);
		for (j = 0; j < nr_objs; j++) {
			if (!vnode_is_local(vnodes[j]))
				continue;

			rlw->oids[rlw->count++] = oids[i];
			/* enlarge the list buffer if full */
			if (rlw->count == list_buffer_size / sizeof(uint64_t)) {
				list_buffer_size *= 2;
				rlw->oids = xrealloc(rlw->oids,
						     list_buffer_size);
			}
			break;
		}
	}

	xqsort(rlw->oids, rlw->count, obj_cmp);
}

/* Prepare the object list that belongs to this node */
static void prepare_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_list_work *rlw = container_of(rw,
						      struct recovery_list_work,
						      base);
	int nr_nodes = rw->cur_vinfo->nr_nodes;
	int start = random() % nr_nodes, i, end = nr_nodes;
	uint64_t *oids;
	struct sd_node *nodes;

	if (node_is_gateway_only())
		return;

	sd_debug("%u", rw->epoch);
	wait_get_vdi_bitmap_done();

	nodes = xmalloc(sizeof(struct sd_node) * nr_nodes);
	nodes_to_buffer(&rw->cur_vinfo->nroot, nodes);
again:
	/* We need to start at random node for better load balance */
	for (i = start; i < end; i++) {
		size_t nr_oids;
		struct sd_node *node = nodes + i;

		if (uatomic_read(&next_rinfo)) {
			sd_debug("go to the next recovery");
			goto out;
		}

		oids = fetch_object_list(node, rw->epoch, &nr_oids);
		if (!oids)
			continue;
		screen_object_list(rlw, oids, nr_oids);
		free(oids);
	}

	if (start != 0) {
		end = start;
		start = 0;
		goto again;
	}

	sd_debug("%"PRIu64, rlw->count);
out:
	free(nodes);
}

int start_recovery(struct vnode_info *cur_vinfo, struct vnode_info *old_vinfo,
		   bool epoch_lifted)
{
	struct recovery_info *rinfo;

	rinfo = xzalloc(sizeof(struct recovery_info));
	rinfo->state = RW_PREPARE_LIST;
	rinfo->epoch = sys->cinfo.epoch;
	rinfo->tgt_epoch = epoch_lifted ? sys->cinfo.epoch - 1 :
		sys->cinfo.epoch;
	rinfo->count = 0;
	rinfo->max_epoch = sys->cinfo.epoch;
	rinfo->vinfo_array = xzalloc(sizeof(struct vnode_info *) *
				     rinfo->max_epoch);
	sd_init_mutex(&rinfo->vinfo_lock);
	if (epoch_lifted)
		rinfo->notify_complete = true; /* Reweight or node recovery */
	else
		rinfo->notify_complete = false; /* MD recovery */

	rinfo->cur_vinfo = grab_vnode_info(cur_vinfo);
	rinfo->old_vinfo = grab_vnode_info(old_vinfo);

	if (!node_is_gateway_only()) {
		int ret;
		ret = sd_store->update_epoch(rinfo->tgt_epoch);
		if (ret != SD_RES_SUCCESS)
			sd_err("failed to update epoch %"PRIu32 " %s",
			       rinfo->tgt_epoch, sd_strerror(ret));
	}

	if (main_thread_get(current_rinfo) != NULL) {
		/* skip the previous epoch recovery */
		struct recovery_info *nrinfo;
		nrinfo = uatomic_xchg_ptr(&next_rinfo, rinfo);
		if (nrinfo)
			free_recovery_info(nrinfo);
		sd_debug("recovery skipped");
	} else {
		main_thread_set(current_rinfo, rinfo);
		queue_recovery_work(rinfo);
	}
	wakeup_requests_on_epoch();
	return 0;
}

static void queue_recovery_work(struct recovery_info *rinfo)
{
	struct recovery_work *rw;
	struct recovery_list_work *rlw;
	struct recovery_obj_work *row;

	switch (rinfo->state) {
	case RW_PREPARE_LIST:
		rlw = xzalloc(sizeof(*rlw));
		rlw->oids = xmalloc(list_buffer_size);

		rw = &rlw->base;
		rw->work.fn = prepare_object_list;
		rw->work.done = finish_object_list;
		break;
	case RW_RECOVER_OBJ:
		row = xzalloc(sizeof(*row));
		row->oid = rinfo->oids[rinfo->next];

		rw = &row->base;
		rw->work.fn = recover_object_work;
		rw->work.done = recover_object_main;
		break;
	case RW_NOTIFY_COMPLETION:
		rw = xzalloc(sizeof(*rw));
		rw->work.fn = notify_recovery_completion_work;
		rw->work.done = notify_recovery_completion_main;
		break;
	default:
		panic("unknown recovery state %d", rinfo->state);
		break;
	}

	rw->epoch = rinfo->epoch;
	rw->tgt_epoch = rinfo->tgt_epoch;
	rw->rinfo = rinfo;
	rw->cur_vinfo = grab_vnode_info(rinfo->cur_vinfo);
	rw->old_vinfo = grab_vnode_info(rinfo->old_vinfo);

	queue_work(sys->recovery_wqueue, &rw->work);
}

void get_recovery_state(struct recovery_state *state)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	memset(state, 0, sizeof(*state));

	if (!rinfo) {
		state->in_recovery = 0;
		return;
	}

	state->in_recovery = 1;
	state->state = rinfo->state;
	state->nr_finished = rinfo->done;
	state->nr_total = rinfo->count;
}
