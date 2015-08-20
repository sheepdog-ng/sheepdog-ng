/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheepdog.h"
#include "internal.h"
#include "internal_proto.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>

static ssize_t net_read(int fd, void *buf, size_t count)
{
	char *p = buf;
	ssize_t sum = 0;
	while (count != 0) {
		ssize_t loaded = 0;
		while (true) {
			loaded = read(fd, p, count);
			if (unlikely(loaded < 0) && (errno == EINTR))
				continue;
			break;
		}

		if (unlikely(loaded < 0))
			return -1;
		if (unlikely(loaded == 0))
			return sum;

		count -= loaded;
		p += loaded;
		sum += loaded;
	}

	return sum;
}

static ssize_t net_write(int fd, void *buf, size_t count)
{
	char *p = buf;
	ssize_t sum = 0;
	while (count != 0) {
		ssize_t written = 0;
		while (true) {
			written = write(fd, p, count);
			if (unlikely(written < 0) && (errno == EINTR))
				continue;
			break;
		}

		if (unlikely(written < 0))
			return -1;
		if (unlikely(written == 0))
			return -1;

		count -= written;
		p += written;
		sum += written;
	}

	return sum;
}

int sheep_submit_sdreq(struct sd_cluster *c, struct sd_req *hdr,
			      void *data, uint32_t wlen)
{
	int ret;

	sd_mutex_lock(&c->submit_mutex);
	if (!uatomic_is_true(&c->connected)) {
		ret = -SD_RES_EIO;
		goto out;
	}

	ret = net_write(c->sockfd, hdr, sizeof(*hdr));
	if (ret != sizeof(*hdr)) {
		ret = -SD_RES_EIO;
		goto out;
	}

	if (wlen) {
		ret = net_write(c->sockfd, data, wlen);
		if (ret != wlen)
			ret = -SD_RES_EIO;
	}

out:
	if (ret < 0)
		uatomic_set_false(&c->connected);

	sd_mutex_unlock(&c->submit_mutex);

	return ret;
}

/* Run the request synchronously */
int sd_run_sdreq(struct sd_cluster *c, struct sd_req *hdr, void *data)
{
	struct sd_request *req = alloc_request(c, data,
		hdr->data_length, SHEEP_CTL);
	int ret;

	if (!req)
		return SD_RES_SYSTEM_ERROR;

	req->hdr = hdr;
	queue_request(req);

	eventfd_xread(req->efd);
	ret = req->ret;
	free_request(req);

	return ret;
}

static void aio_end_request(struct sd_request *req, int ret)
{
	req->ret = ret;
	eventfd_xwrite(req->efd, 1);
}

static void aio_rw_done(struct sheep_aiocb *aiocb)
{
	aio_end_request(aiocb->request, aiocb->ret);
	free(aiocb);
}

static struct sheep_aiocb *sheep_aiocb_setup(struct sd_request *req)
{
	struct sheep_aiocb *aiocb = xmalloc(sizeof(*aiocb));

	aiocb->offset = req->offset;
	aiocb->length = req->length;
	aiocb->ret = 0;
	aiocb->buf_iter = 0;
	aiocb->request = req;
	aiocb->buf = req->data;
	aiocb->aio_done_func = aio_rw_done;
	uatomic_set(&aiocb->nr_requests, 0);

	return aiocb;
}

struct sheep_request *alloc_sheep_request(struct sheep_aiocb *aiocb,
						 uint64_t oid, uint64_t cow_oid,
						 int len, int offset)
{
	struct sheep_request *req = xzalloc(sizeof(*req));
	struct sd_cluster *c = aiocb->request->cluster;

	req->offset = offset;
	req->length = len;
	req->oid = oid;
	req->cow_oid = cow_oid;
	req->aiocb = aiocb;
	req->buf = aiocb->buf + aiocb->buf_iter;
	req->seq_num = uatomic_add_return(&c->seq_num, 1);
	req->opcode = aiocb->request->opcode;
	aiocb->buf_iter += len;

	INIT_LIST_NODE(&req->list);
	uatomic_inc(&aiocb->nr_requests);

	return req;
}

uint32_t sheep_inode_get_vid(struct sd_request *req, uint32_t idx)
{
	uint32_t vid;

	sd_read_lock(&req->vdi->lock);
	vid = req->vdi->inode->data_vdi_id[idx];
	sd_rw_unlock(&req->vdi->lock);

	return vid;
}

static int connect_to(char *ip, unsigned int port)
{
	int fd, ret, value = 1;
	struct sockaddr_in addr;
	struct linger linger_opt = {1, 0};
	struct timeval to_send = {NET_SEND_TIMEOUT, 0},
			to_recv = {NET_RECV_TIMEOUT, 0};

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		ret = -1;
		goto err;
	}

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		ret = -1;
		goto err;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger_opt,
			 sizeof(linger_opt));
	if (ret < 0)
		goto err_close;

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
	if (ret < 0)
		goto err_close;

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		goto err_close;

	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to_recv,
			sizeof(to_recv));
	if (ret < 0)
		goto err_close;

	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &to_send,
			sizeof(to_send));
	if (ret < 0)
		goto err_close;

	fprintf(stderr, "Now connected to %s:%d (fd:%d)\n", ip, port, fd);
	return fd;

err_close:
	close(fd);
err:
	return ret;
}

static void do_reconnect(struct sd_cluster *c)
{
	struct sheep_host *p = NULL;
	int fd = -1, retry;

	sd_mutex_lock(&c->submit_mutex);
	close(c->sockfd);
	while (fd < 0) {
		retry = c->nr_hosts;
		while (retry--) {
			p = c->hosts + c->host_index;
			fprintf(stderr, "\nReconnecting to %s:%d...\n",
					p->addr, p->port);
			fd = connect_to(p->addr, p->port);
			c->host_index = (c->host_index + 1) % c->nr_hosts;
			if (fd > 0)
				break;
		}
	}

	c->sockfd = fd;
	uatomic_set_true(&c->connected);
	sd_mutex_unlock(&c->submit_mutex);
}

static int do_submit_sheep_request(struct sheep_request *req)
{
	struct sd_req hdr = {}, *hdr_ptr = NULL;
	struct sd_cluster *c = req->aiocb->request->cluster;
	int ret = 0;
	uint32_t wlen = 0;

	hdr.id = req->seq_num;
	hdr.data_length = req->length;
	hdr.obj.oid = req->oid;
	hdr.obj.cow_oid = req->cow_oid;
	hdr.obj.offset = req->offset;

	switch (req->opcode) {
	case VDI_CREATE:
	case VDI_WRITE:
		if (req->opcode == VDI_CREATE)
			hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		else
			hdr.opcode = SD_OP_WRITE_OBJ;
		hdr.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_DIRECT;
		if (req->cow_oid)
			hdr.flags |= SD_FLAG_CMD_COW;
		ret = sheep_submit_sdreq(c, &hdr, req->buf, req->length);
		break;
	case VDI_READ:
		hdr.opcode = SD_OP_READ_OBJ;
		ret = sheep_submit_sdreq(c, &hdr, NULL, 0);
		break;
	case SHEEP_CTL:
		hdr_ptr = req->aiocb->request->hdr;
		if (hdr_ptr->flags & SD_FLAG_CMD_WRITE)
			wlen = hdr_ptr->data_length;
		ret = sheep_submit_sdreq(c, hdr_ptr, req->buf, wlen);
		break;
	}

	return ret;
}

static void reconnect_and_resend(struct sd_cluster *c)
{
	struct sheep_request *request;
	int ret;
again:
	do_reconnect(c);

	sd_read_lock(&c->inflight_lock);

	list_for_each_entry(request, &c->inflight_list, list) {
		ret = do_submit_sheep_request(request);
		if (ret > 0) {
			eventfd_xwrite(c->reply_fd, 1);
		} else {
			sd_rw_unlock(&c->inflight_lock);
			goto again;
		}
	}

	sd_rw_unlock(&c->inflight_lock);
}

int submit_sheep_request(struct sheep_request *req)
{
	int ret;
	struct sd_cluster *c = req->aiocb->request->cluster;

	sd_write_lock(&c->inflight_lock);
	list_add_tail(&req->list, &c->inflight_list);
	sd_rw_unlock(&c->inflight_lock);

	ret = do_submit_sheep_request(req);
	eventfd_xwrite(c->reply_fd, 1);

	return ret;
}

void submit_blocking_sheep_request(struct sd_cluster *c, uint64_t oid)
{
	struct sheep_request *req;

	sd_write_lock(&c->blocking_lock);
	list_for_each_entry(req, &c->blocking_list, list) {
		if (req->oid != oid)
			continue;
		list_del(&req->list);
		submit_sheep_request(req);
	}
	sd_rw_unlock(&c->blocking_lock);
}

struct sheep_request *find_inflight_request_oid(struct sd_cluster *c,
						       uint64_t oid)
{
	struct sheep_request *req;

	sd_read_lock(&c->inflight_lock);
	list_for_each_entry(req, &c->inflight_list, list) {
		if (req->oid == oid) {
			sd_rw_unlock(&c->inflight_lock);
			return req;
		}
	}
	sd_rw_unlock(&c->inflight_lock);
	return NULL;
}

static int sheep_aiocb_submit(struct sheep_aiocb *aiocb)
{
	struct sd_request *request = aiocb->request;
	uint8_t opcode = request->opcode;
	int ret = -1;

	aiocb->op = get_sd_op(opcode);

	if (aiocb->op != NULL && aiocb->op->request_process)
		ret = aiocb->op->request_process(aiocb);

	return ret;
}

static int submit_request(struct sd_request *req)
{
	struct sheep_aiocb *aiocb = sheep_aiocb_setup(req);

	return sheep_aiocb_submit(aiocb);
}

static void *request_handler(void *data)
{
	struct sd_request *req;
	struct sd_cluster *c = data;

	while (!uatomic_is_true(&c->stop_request_handler) ||
	       !list_empty(&c->request_list)) {

		eventfd_xread(c->request_fd);
		sd_write_lock(&c->request_lock);
		if (list_empty(&c->request_list)) {
			sd_rw_unlock(&c->request_lock);
			continue;
		}
		req = list_first_entry(&c->request_list, struct sd_request,
				       list);
		list_del(&req->list);
		sd_rw_unlock(&c->request_lock);
		submit_request(req);
	}
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

static struct sheep_request *find_inflight_request(struct sd_cluster *c,
						    uint32_t seq_num)
{
	struct sheep_request *req;

	sd_read_lock(&c->inflight_lock);
	list_for_each_entry(req, &c->inflight_list, list) {
		if (req->seq_num == seq_num)
			goto out;
	}
	req = NULL;
out:
	sd_rw_unlock(&c->inflight_lock);
	return req;
}

int end_sheep_request(struct sheep_request *req)
{
	struct sheep_aiocb *aiocb = req->aiocb;

	if (uatomic_sub_return(&aiocb->nr_requests, 1) <= 0)
		aiocb->aio_done_func(aiocb);

	free(req);

	return 0;
}

static int sheep_handle_reply(struct sd_cluster *c)
{
	struct sd_rsp rsp = {};
	struct sheep_request *req;
	struct sheep_aiocb *aiocb;
	int ret;
	char *temp;

	if (unlikely(!uatomic_is_true(&c->connected)))
		goto reconnect;

	ret = net_read(c->sockfd, (char *)&rsp, sizeof(rsp));
	if (ret != sizeof(rsp))
		goto err;

	req = find_inflight_request(c, rsp.id);
	if (!req)
		/*
		 * Some request might be sent more than once because of
		 * reconnection, we just discard the duplicated one.
		 */
		goto discard;

	if (rsp.data_length > 0) {
		ret = net_read(c->sockfd, req->buf, rsp.data_length);
		if (ret != rsp.data_length)
			goto err;
	}

	sd_write_lock(&c->inflight_lock);
	list_del(&req->list);
	sd_rw_unlock(&c->inflight_lock);

	aiocb = req->aiocb;
	aiocb->op = get_sd_op(req->opcode);
	if (aiocb->op != NULL && !!aiocb->op->response_process)
		ret = aiocb->op->response_process(req, &rsp);

	end_sheep_request(req);

	return ret;
err:
	uatomic_set_false(&c->connected);
reconnect:
	reconnect_and_resend(c);
	return -1;
discard:
	if (rsp.data_length == 0)
		return 0;
	temp = xmalloc(rsp.data_length);
	net_read(c->sockfd, temp, rsp.data_length);
	free(temp);
	return 0;
}

static void *reply_handler(void *data)
{
	struct sd_cluster *c = data;

	while (!uatomic_is_true(&c->stop_request_handler) ||
	       !list_empty(&c->inflight_list)) {
		bool empty;
		uint64_t events;

		events = eventfd_xread(c->reply_fd);

		sd_read_lock(&c->inflight_lock);
		empty = list_empty(&c->inflight_list);
		sd_rw_unlock(&c->inflight_lock);

		if (empty)
			continue;

		for (uint64_t i = 0; i < events; i++) {
			int ret = sheep_handle_reply(c);
			if (ret < 0)
				break;
		}

	}
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

static int init_cluster_handlers(struct sd_cluster *c)
{
	pthread_t thread;
	int ret;

	c->request_fd = eventfd(0, 0);
	if (c->request_fd < 0)
		return -SD_RES_SYSTEM_ERROR;

	c->reply_fd = eventfd(0, 0);
	if (c->reply_fd < 0) {
		close(c->request_fd);
		return -SD_RES_SYSTEM_ERROR;
	}

	ret = pthread_create(&thread, NULL, request_handler, c);
	if (ret < 0) {
		close(c->request_fd);
		close(c->reply_fd);
		return ret;
	}
	c->request_thread = thread;
	ret = pthread_create(&thread, NULL, reply_handler, c);
	if (ret < 0) {
		close(c->reply_fd);
		uatomic_set_true(&c->stop_request_handler);
		eventfd_xwrite(c->request_fd, 1);
		pthread_join(c->request_thread, NULL);
		return ret;
	}
	c->reply_thread = thread;

	return SD_RES_SUCCESS;
}

static int get_all_nodes(struct sd_cluster *c)
{
	struct sd_node *nodes = NULL;
	struct sd_req hdr = {};
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned int nodes_size;
	int ret;

	nodes_size = SD_MAX_NODES * sizeof(struct sd_node);
	nodes = xzalloc(nodes_size);

	hdr.opcode = SD_OP_GET_NODE_LIST;
	hdr.proto_ver = SD_SHEEP_PROTO_VER;
	hdr.data_length = nodes_size;

	ret = sd_run_sdreq(c, &hdr, nodes);
	if (ret != SD_RES_SUCCESS) {
		free(nodes);
		return ret;
	}

	int nr_nodes = rsp->data_length / sizeof(struct sd_node);

	c->hosts = xzalloc(nr_nodes * sizeof(struct sheep_host));
	c->nr_hosts = nr_nodes;
	c->host_index = 0;

	for (int i = 0; i < nr_nodes; i++) {
		struct sheep_host *p = c->hosts + i;
		p->port = nodes[i].nid.port;
		if (!inet_ntop(AF_INET, nodes[i].nid.addr + 12,
			p->addr, INET_ADDRSTRLEN)) {
			ret = SD_RES_SYSTEM_ERROR;
			break;
		}
	}

	free(nodes);
	return ret;
}

struct sd_cluster *sd_connect(char *host)
{
	char *ip, *pt, *h = xstrdup(host);
	unsigned port;
	int fd, ret;
	struct sd_cluster *c = NULL;

	ip = strtok(h, ":");
	if (!ip) {
		errno = SD_RES_INVALID_PARMS;
		goto err;
	}

	pt = strtok(NULL, ":");
	if (!pt) {
		errno = SD_RES_INVALID_PARMS;
		goto err;
	}

	if (sscanf(pt, "%u", &port) != 1) {
		errno = SD_RES_INVALID_PARMS;
		goto err;
	}

	fd = connect_to(ip, port);
	if (fd < 0) {
		errno = SD_RES_SYSTEM_ERROR;
		goto err;
	}

	c = xzalloc(sizeof(*c));
	c->sockfd = fd;

	ret = init_cluster_handlers(c);
	if (ret < 0) {
		errno = -ret;
		goto err_close;
	};

	signal(SIGPIPE, SIG_IGN);

	uatomic_set_true(&c->connected);
	INIT_LIST_HEAD(&c->request_list);
	INIT_LIST_HEAD(&c->inflight_list);
	INIT_LIST_HEAD(&c->blocking_list);
	sd_init_rw_lock(&c->request_lock);
	sd_init_rw_lock(&c->inflight_lock);
	sd_init_rw_lock(&c->blocking_lock);
	sd_init_mutex(&c->submit_mutex);

	ret = get_all_nodes(c);
	if (ret != SD_RES_SUCCESS) {
		errno = ret;
		goto err_close;
	}

	free(h);
	return c;

err_close:
	close(fd);
	free(c->hosts);
	free(c);
err:
	free(h);
	return NULL;
}

int sd_disconnect(struct sd_cluster *c)
{
	uatomic_set_true(&c->stop_request_handler);
	uatomic_set_true(&c->stop_reply_handler);
	eventfd_xwrite(c->request_fd, 1);
	eventfd_xwrite(c->reply_fd, 1);
	pthread_join(c->request_thread, NULL);
	pthread_join(c->reply_thread, NULL);
	sd_destroy_rw_lock(&c->request_lock);
	sd_destroy_rw_lock(&c->inflight_lock);
	sd_destroy_rw_lock(&c->blocking_lock);
	sd_destroy_mutex(&c->submit_mutex);
	close(c->request_fd);
	close(c->reply_fd);
	close(c->sockfd);
	free(c->hosts);
	free(c);

	return SD_RES_SUCCESS;
}
