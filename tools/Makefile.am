MAINTAINERCLEANFILES	= Makefile.in

noinst_PROGRAMS		=

sbin_PROGRAMS =

sbin_SCRIPTS =

if BUILD_ZOOKEEPER
noinst_PROGRAMS		+= zk_control

zk_control_SOURCES = zk_control.c

zk_control_LDADD	= -lzookeeper_mt
endif

if BUILD_LIVEPATCH
sbin_PROGRAMS += create-diff-object

sbin_SCRIPTS += livepatch-build/livepatch-build

AM_CPPFLAGS		= -I$(top_builddir)/include -Ilivepatch-build -Ilivepatch-build/insn

create_diff_object_SOURCES = livepatch-build/create-diff-object.c \
							 livepatch-build/lookup.c \
							 livepatch-build/insn/insn.c \
							 livepatch-build/insn/inat.c

create_diff_object_LDADD = -lelf
endif
