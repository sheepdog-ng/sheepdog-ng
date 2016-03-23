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

#include "dog.h"
#include "internal_proto.h"

static int livepatch_patch(int argc, char **argv)
{
	const char *patch = argv[optind];
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_LIVEPATCH_PATCH);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = strlen(patch) + 1;

	ret = dog_exec_req(&sd_nid, &hdr, (void *)patch);
	if (ret < 0)
		return EXIT_SYSFAIL;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	default:
		sd_err("unknown error (%s)", sd_strerror(rsp->result));
		return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static int livepatch_unpatch(int argc, char **argv)
{
	const char *patch = argv[optind];
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_LIVEPATCH_UNPATCH);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = strlen(patch) + 1;

	ret = dog_exec_req(&sd_nid, &hdr, (void *)patch);
	if (ret < 0)
		return EXIT_SYSFAIL;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	default:
		sd_err("unknown error (%s)", sd_strerror(rsp->result));
		return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static int livepatch_status(int argc, char **argv)
{
#define LIVEPATCH_BUF_LEN (1024 * 1024 * 1)
	char buf[LIVEPATCH_BUF_LEN];
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_LIVEPATCH_STATUS);
	hdr.data_length = sizeof(buf);

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0)
		return EXIT_SYSFAIL;
	switch (rsp->result) {
		sd_err("%s", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

    printf("Patches\t\t\tFunctions\n");
    printf("%s", buf);

	return EXIT_SUCCESS;
}

static int livepatch_parser(int ch, const char *opt)
{
	return 0;
}

/* Subcommand list of livepatch */
static struct subcommand livepatch_cmd[] = {
	{"patch", "<livepatch>", "aph", "patch livepatch", NULL,
	 CMD_NEED_ARG, livepatch_patch},
	{"unpatch", "<livepatch>", "aph", "unpatch livepatch", NULL,
	 CMD_NEED_ARG, livepatch_unpatch},
	{"status", NULL, "aph", "show info of livepatchs", NULL,
	 0, livepatch_status},
	{NULL},
};

struct command livepatch_command = {
	"livepatch",
	livepatch_cmd,
	livepatch_parser
};
