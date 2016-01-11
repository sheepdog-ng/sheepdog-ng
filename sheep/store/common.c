/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <libgen.h>

#include "sheep_priv.h"

char *obj_path;
char *epoch_path;

struct store_driver *sd_store;
LIST_HEAD(store_drivers);

#define sector_algined(x) ({ ((x) & (SECTOR_SIZE - 1)) == 0; })

static inline bool iocb_is_aligned(const struct siocb *iocb)
{
	return  sector_algined(iocb->offset) && sector_algined(iocb->length);
}

int prepare_iocb(uint64_t oid, const struct siocb *iocb, bool create)
{
	int flags = O_DSYNC | O_RDWR;

	if (sys->nosync == true)
		flags &= ~O_DSYNC;

	if (sys->backend_dio && iocb_is_aligned(iocb)) {
		if (!is_aligned_to_pagesize(iocb->buf))
			panic("Memory isn't aligned to pagesize %p", iocb->buf);
		flags |= O_DIRECT;
	}

	if (create)
		flags |= O_CREAT | O_EXCL;

	return flags;
}

int err_to_sderr(const char *path, uint64_t oid, int err)
{
	struct stat s;
	char p[PATH_MAX], *dir;

	/* Use a temporary buffer since dirname() may modify its argument. */
	pstrcpy(p, sizeof(p), path);
	dir = dirname(p);

	sd_debug("%s", path);
	switch (err) {
	case ENOENT:
		if (stat(dir, &s) < 0) {
			sd_err("%s corrupted", dir);
			return md_handle_eio(dir);
		}
		sd_debug("object %016" PRIx64 " not found locally", oid);
		return SD_RES_NO_OBJ;
	case ENOSPC:
		/* TODO: stop automatic recovery */
		sd_err("diskfull, oid=%"PRIx64, oid);
		return SD_RES_NO_SPACE;
	case EMFILE:
	case ENFILE:
	case EINTR:
	case EAGAIN:
	case EEXIST:
		sd_err("%m, oid=%"PRIx64, oid);
		/* make gateway try again */
		return SD_RES_NETWORK_ERROR;
	default:
		sd_err("oid=%"PRIx64", %m", oid);
		return md_handle_eio(dir);
	}
}

int update_epoch_log(uint32_t epoch, struct sd_node *nodes,
		      size_t nr_nodes, bool force_create)
{
	int ret, len, nodes_len;
	time_t t;
	char path[PATH_MAX], *buf;

	sd_debug("update epoch: %d, %zu", epoch, nr_nodes);

	/* Piggyback the epoch creation time for 'dog cluster info' */
	time(&t);
	nodes_len = nr_nodes * sizeof(struct sd_node);
	len = nodes_len + sizeof(time_t);
	buf = xmalloc(len);
	memcpy(buf, nodes, nodes_len);
	memcpy(buf + nodes_len, &t, sizeof(time_t));

	/*
	 * rb field is unused in epoch file, zero-filling it
	 * is good for epoch file recovery because it is unified
	 */
	for (int i = 0; i < nr_nodes; i++)
		memset(buf + i * sizeof(struct sd_node)
				+ offsetof(struct sd_node, rb),
				0, sizeof(struct rb_node));

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);

	ret = atomic_create_and_write(path, buf, len, force_create);

	free(buf);
	return ret;
}

static int do_epoch_log_read(uint32_t epoch, struct sd_node *nodes, int len,
			     int *nr_nodes, time_t *timestamp)
{
	int fd, ret, buf_len;
	char path[PATH_MAX];
	struct stat epoch_stat;

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		sd_debug("failed to open epoch %"PRIu32" log, %m", epoch);
		goto err;
	}

	memset(&epoch_stat, 0, sizeof(epoch_stat));
	ret = fstat(fd, &epoch_stat);
	if (ret < 0) {
		sd_err("failed to stat epoch %"PRIu32" log, %m", epoch);
		goto err;
	}

	buf_len = epoch_stat.st_size - sizeof(*timestamp);
	if (buf_len < 0) {
		sd_err("invalid epoch %"PRIu32" log", epoch);
		goto err;
	}
	if (len < buf_len) {
		close(fd);
		return SD_RES_BUFFER_SMALL;
	}

	ret = xread(fd, nodes, buf_len);
	if (ret < 0) {
		sd_err("failed to read epoch %"PRIu32" log, %m", epoch);
		goto err;
	}

	/* Broken epoch, just ignore */
	if (ret % sizeof(struct sd_node) != 0) {
		sd_err("invalid epoch %"PRIu32" log", epoch);
		goto err;
	}

	*nr_nodes = ret / sizeof(struct sd_node);

	if (timestamp) {
		ret = xread(fd, timestamp, sizeof(*timestamp));
		if (ret != sizeof(*timestamp)) {
			sd_err("invalid epoch %"PRIu32" log", epoch);
			goto err;
		}
	}

	close(fd);
	return SD_RES_SUCCESS;
err:
	if (fd >= 0)
		close(fd);
	return SD_RES_NO_TAG;
}

int epoch_log_read(uint32_t epoch, struct sd_node *nodes,
				int len, int *nr_nodes)
{
	return do_epoch_log_read(epoch, nodes, len, nr_nodes, NULL);
}

int epoch_log_read_with_timestamp(uint32_t epoch, struct sd_node *nodes,
				int len, int *nr_nodes, time_t *timestamp)
{
	return do_epoch_log_read(epoch, nodes, len, nr_nodes, timestamp);
}

uint32_t get_latest_epoch(void)
{
	DIR *dir;
	struct dirent *d;
	uint32_t e, epoch = 0;
	char *p;

	dir = opendir(epoch_path);
	if (!dir)
		panic("failed to get the latest epoch: %m");

	while ((d = readdir(dir))) {
		e = strtol(d->d_name, &p, 10);
		if (d->d_name == p)
			continue;

		if (strlen(d->d_name) != 8)
			continue;

		if (e > epoch)
			epoch = e;
	}
	closedir(dir);

	return epoch;
}

int lock_base_dir(const char *d)
{
#define LOCK_PATH "/lock"
	char *lock_path;
	int ret = 0;
	int fd, len = strlen(d) + strlen(LOCK_PATH) + 1;

	lock_path = xzalloc(len);
	snprintf(lock_path, len, "%s" LOCK_PATH, d);

	fd = open(lock_path, O_WRONLY|O_CREAT, sd_def_fmode);
	if (fd < 0) {
		sd_err("failed to open lock file %s (%m)", lock_path);
		ret = -1;
		goto out;
	}

	if (lockf(fd, F_TLOCK, 1) < 0) {
		if (errno == EACCES || errno == EAGAIN)
			sd_err("another sheep daemon is using %s", d);
		else
			sd_err("unable to get base dir lock (%m)");
		ret = -1;
		goto out;
	}

out:
	free(lock_path);
	return ret;
}

int init_base_path(const char *d)
{
	if (xmkdir(d, sd_def_dmode) < 0) {
		sd_err("cannot create the directory %s (%m)", d);
		return -1;
	}

	return 0;
}

static inline int check_path_len(const char *path)
{
	int len = strlen(path);
	if (len > PATH_MAX) {
		sd_err("insanely long object directory %s", path);
		return -1;
	}

	return 0;
}

static int is_meta_store(const char *path)
{
	char conf[PATH_MAX];
	char epoch[PATH_MAX];

	snprintf(conf, PATH_MAX, "%s/config", path);
	snprintf(epoch, PATH_MAX, "%s/epoch", path);
	if (!access(conf, R_OK) && !access(epoch, R_OK))
		return true;

	return false;
}

static int init_obj_path(const char *base_path, char *argp)
{
	char *p;
	int len;

	if (check_path_len(base_path) < 0)
		return -1;

#define OBJ_PATH "/obj"
	len = strlen(base_path) + strlen(OBJ_PATH) + 1;
	obj_path = xzalloc(len);
	snprintf(obj_path, len, "%s" OBJ_PATH, base_path);

	/* Eat up the first component */
	strtok(argp, ",");
	p = strtok(NULL, ",");
	if (!p) {
		/*
		 * If We have only one path, meta-store and object-store share
		 * it. This is helpful to upgrade old sheep cluster to
		 * the MD-enabled.
		 */
		md_add_disk(obj_path, false);
	} else {
		do {
			if (is_meta_store(p)) {
				sd_err("%s is meta-store, abort", p);
				return -1;
			}
			md_add_disk(p, false);
		} while ((p = strtok(NULL, ",")));
	}

	if (md_nr_disks() <= 0) {
		sd_err("There isn't any available disk!");
		return -1;
	}

	return xmkdir(obj_path, sd_def_dmode);
}

static int init_epoch_path(const char *base_path)
{
#define EPOCH_PATH "/epoch/"
	int len = strlen(base_path) + strlen(EPOCH_PATH) + 1;
	epoch_path = xzalloc(len);
	snprintf(epoch_path, len, "%s" EPOCH_PATH, base_path);

	return xmkdir(epoch_path, sd_def_dmode);
}

/*
 * If the node is gateway, this function only finds the store driver.
 * Otherwise, this function initializes the backend store
 */
int init_store_driver(bool is_gateway)
{
	char driver_name[STORE_LEN], *p;

	pstrcpy(driver_name, sizeof(driver_name), (char *)sys->cinfo.store);

	p = memchr(driver_name, '\0', STORE_LEN);
	if (!p) {
		/*
		 * If the driver name is not NUL terminated we are in deep
		 * trouble, let's get out here.
		 */
		sd_debug("store name not NUL terminated");
		return SD_RES_NO_STORE;
	}

	/*
	 * The store file might not exist in case this is a new sheep that
	 * never joined a cluster before.
	 */
	if (p == driver_name)
		return 0;

	sd_store = find_store_driver(driver_name);
	if (!sd_store) {
		sd_debug("store %s not found", driver_name);
		return SD_RES_NO_STORE;
	}

	if (is_gateway)
		return SD_RES_SUCCESS;

	return sd_store->init();
}

int init_disk_space(const char *base_path)
{
	int ret = SD_RES_SUCCESS;
	uint64_t space_size = 0, mds;
	struct statvfs fs;

	if (sys->gateway_only)
		goto out;

	/* We need to init md even we don't need to update sapce */
	mds = md_init_space();

	/* If it is restarted */
	ret = get_node_space(&space_size);
	if (space_size != 0) {
		sys->disk_space = space_size;
		goto out;
	}

	/* User has specified the space at startup */
	if (sys->disk_space) {
		ret = set_node_space(sys->disk_space);
		goto out;
	}

	if (mds) {
		sys->disk_space = mds;
	} else {
		ret = statvfs(base_path, &fs);
		if (ret < 0) {
			sd_debug("get disk space failed %m");
			ret = SD_RES_EIO;
			goto out;
		}
		sys->disk_space = (uint64_t)fs.f_frsize * fs.f_bavail;
	}

	ret = set_node_space(sys->disk_space);
out:
	sd_debug("disk free space is %" PRIu64, sys->disk_space);
	return ret;
}

/* Initialize all the global pathnames used internally */
int init_global_pathnames(const char *d, char *argp)
{
	int ret;

	ret = init_obj_path(d, argp);
	if (ret)
		return ret;

	ret = init_epoch_path(d);
	if (ret)
		return ret;

	init_config_path(d);

	return 0;
}

/* Write data to both local object cache (if enabled) and backends */
int sd_write_object(uint64_t oid, char *data, unsigned int datalen,
		    uint64_t offset, bool create)
{
	struct sd_req hdr;
	int ret;

	if (sys->enable_object_cache && object_is_cached(oid)) {
		ret = object_cache_write(oid, data, datalen, offset,
					 create);
		if (ret == SD_RES_NO_CACHE)
			goto forward_write;

		if (ret != 0) {
			sd_err("write cache failed %" PRIx64 " %" PRIx32, oid,
			       ret);
			return ret;
		}
	}

forward_write:
	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = datalen;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = exec_local_req(&hdr, data);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to write object %" PRIx64 ", %s", oid,
			   sd_strerror(ret));

	return ret;
}

int read_backend_object(uint64_t oid, char *data, unsigned int datalen,
			uint64_t offset)
{
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.data_length = datalen;
	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	return exec_local_req(&hdr, data);
}

/*
 * Read data firstly from local object cache(if enabled), if fail,
 * try read backends
 */
int sd_read_object(uint64_t oid, char *data, unsigned int datalen,
		   uint64_t offset)
{
	int ret;

	if (sys->enable_object_cache && object_is_cached(oid)) {
		ret = object_cache_read(oid, data, datalen, offset);
		if (ret != SD_RES_SUCCESS) {
			sd_err("try forward read %" PRIx64 " %s", oid,
			       sd_strerror(ret));
			goto forward_read;
		}
		return ret;
	}

forward_read:
	return read_backend_object(oid, data, datalen, offset);
}

int sd_remove_object(uint64_t oid)
{
	struct sd_req hdr;
	int ret;

	if (sys->enable_object_cache && object_is_cached(oid)) {
		ret = object_cache_remove(oid);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}

	sd_init_req(&hdr, SD_OP_REMOVE_OBJ);
	hdr.obj.oid = oid;

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to remove object %" PRIx64 ", %s", oid,
		       sd_strerror(ret));

	return ret;
}

int sd_discard_object(uint64_t oid)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_DISCARD_OBJ);
	hdr.obj.oid = oid;

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to discard data obj %"PRIu64" %s", oid,
		       sd_strerror(ret));

	return ret;
}


/*
 * Cow object: shared by more than one vdi. None-cow object is not shared by
 * other vdi.
 *
 * When we unref the object, for
 * cow: we send a unref message to the cluster.
 * none-cow: we simply send a remove message to the cluster.
 *
 * When the references of the object become zero (no ref), then we can remove
 * the object along with its ledger object, which bookkeeps the references of
 * this object.
 */
int sd_unref_object(uint64_t data_oid, uint32_t generation, uint32_t refcnt)
{
	struct sd_req hdr;
	int ret;

	sd_debug("%"PRIx64", ref %" PRId32 ", count %" PRId32,
		 data_oid, generation, refcnt);

	/* No ledger created, so just remove data object */
	if (generation == 0 && refcnt == 0)
		return sd_remove_object(data_oid);

	sd_init_req(&hdr, SD_OP_UNREF_OBJ);
	hdr.ref.oid = data_oid;
	hdr.ref.generation = generation;
	hdr.ref.count = refcnt;

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to decrement reference %" PRIx64 ", %s",
		       data_oid, sd_strerror(ret));

	return ret;
}
