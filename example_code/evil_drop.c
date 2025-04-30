/* poc.c */
#include <linux/bpf.h>
#include <stddef.h>        // offsetof
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <socket.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <errno.h>
#include "bpf_insn.h"

#define LOG_BUF_SZ (1 << 16)

void fatal(const char *msg) {
    perror(msg);
    exit(1);
}

int main(void) {
    /* 1) BPF 프로그램 자체 (시작 4바이트 == "evil" 인지 검사) */
    struct bpf_insn prog[] = {
        /* 0: len = ctx->len */
        BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                    offsetof(struct __sk_buff, len)),
        /* 1: if (len < 4) goto allow;  offset = 16 */
        BPF_JMP_IMM(BPF_JLT, BPF_REG_2, 4, 16),

        /* 2: skb_load_bytes(ctx, 0, fp-8, 4) */
        BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_1),      // ctx
        BPF_MOV64_IMM(BPF_REG_ARG2, 0),              // offset = 0
        BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),     
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),    // &stack[-8]
        BPF_MOV64_IMM(BPF_REG_ARG4, 4),              // len = 4
        BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),
//
        ///* 8: buf[0]=='e'?  if not goto allow (offset=18-(8+1)=9) */
        BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_FP, -8),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_5, 'e', 8),
//
        ///*10: buf[1]=='v'?  if not goto allow (offset=18-(10+1)=7) */
        BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_FP, -7),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_5, 'v', 6),
//
        ///*12: buf[2]=='i'?  if not goto allow (offset=18-(12+1)=5) */
        BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_FP, -6),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_5, 'i', 4),
//
        ///*14: buf[3]=='l'?  if not goto allow (offset=18-(14+1)=3) */
        BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_FP, -5),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_5, 'l', 2),
//
        ///*16: match → drop */
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),

        /*18: allow → pass */
        BPF_MOV64_IMM(BPF_REG_0, -1),
        BPF_EXIT_INSN(),
    };

	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_EXIT_INSN(),
	  };

    /* 2) BPF 로드 준비 */
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt  = sizeof(prog) / sizeof(prog[0]),
        .insns     = (uint64_t)prog,
        .license   = (uint64_t)"GPL",
        .log_level = 1,
        .log_size  = LOG_BUF_SZ,
    };
    char *log_buf = malloc(LOG_BUF_SZ);
    if (!log_buf) fatal("malloc");
    attr.log_buf = (uint64_t)log_buf;

    /* 3) BPF 프로그램 로드 */
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr,
                "BPF load failed: %s\nVerifier log:\n%s\n",
                strerror(errno), log_buf);
        exit(1);
    }
    free(log_buf);

	printf("[*] log %s\n", attr.log_buf);

    /* 4) 소켓 생성 및 필터 부착 */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) fatal("socketpair");
    if (setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_BPF,
                   &prog_fd, sizeof(prog_fd)) < 0) fatal("setsockopt");

    /* 5) 테스트: 시작 4바이트가 "evil" 이면 read() 에서 0이, 아니면 그대로 data */
    const char *msgs[] = {       // drop
        "he",    // pass
		"Hello_world", //pass
		"evilPacket" // drop
    };
    for (int i = 0; i < 3; i++) {
        write(sv[1], msgs[i], strlen(msgs[i]));
        char buf[64] = {};
        int n = read(sv[0], buf, sizeof(buf));
        printf("[%s] read returned %d,", msgs[i], n);
        if (n > 0) printf(" data='%.*s'", n, buf);
        printf("\n");
    }

    return 0;
}
