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

#ifndef INTERNAL_H_
#define INTERNAL_H_

/*
 * The timeout is the same as sheep cluster in net.h,
 * But once we failed for sending or writing, we will
 * try to reconnect coutinuously until we get one
 * available sheep node.
 */
#define NET_SEND_TIMEOUT 5 /* second */
#define NET_RECV_TIMEOUT 30 /* second */

enum sheep_request_type {
	VDI_READ = 1,
	VDI_WRITE,
	VDI_CREATE,
	SHEEP_CTL,
};

struct sheep_aiocb {
	struct sd_request *request;
	off_t offset;
	size_t length;
	int ret;
	uint32_t nr_requests;
	char *buf;
	int buf_iter;
	const struct sd_op_template *op;
	void (*aio_done_func)(struct sheep_aiocb *);
};

struct sheep_request {
	struct list_node list;
	struct sheep_aiocb *aiocb;
	uint64_t oid;
	uint64_t cow_oid;
	uint32_t seq_num;
	uint8_t opcode;
	uint32_t offset;
	uint32_t length;
	char *buf;
};

struct sd_op_template {
	const char *name;
	int (*request_process)(struct sheep_aiocb *aiocb);
	int (*response_process)(struct sheep_request *req, struct sd_rsp *rsp);
};

int end_sheep_request(struct sheep_request *req);
int submit_sheep_request(struct sheep_request *req);

const struct sd_op_template *get_sd_op(uint8_t opcode);

#endif
