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

#define __ASSEMBLY__

#include "livepatch.h"

#define _ALIGN_TEXT .align 16, 0x90

#define ENTRY(x) \
        .text; _ALIGN_TEXT; .globl x; .type x,@function; x:

ENTRY(livepatch_caller)
    subq $0x38, %rsp
    movq %rax, (%rsp)
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %rsi, 24(%rsp)
    movq %rdi, 32(%rsp)
    movq %r8, 40(%rsp)
    movq %r9, 48(%rsp)

    movq 0x38(%rsp), %rdi
    leaq 0x38(%rsp), %rsi
    subq $INSN_SIZE, %rdi

    call livepatch_handler

    movq 48(%rsp), %r9
    movq 40(%rsp), %r8
    movq 32(%rsp), %rdi
    movq 24(%rsp), %rsi
    movq 16(%rsp), %rdx
    movq 8(%rsp), %rcx
    movq (%rsp), %rax
    addq $0x38, %rsp
    retq
