/* poc.c */
#include <linux/bpf.h>
#include <stddef.h>        // offsetof
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

int bpf(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int map_create(int val_size, int max_entries) {
  union bpf_attr attr = {
    .map_type    = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = val_size,
    .max_entries = max_entries
  };
  int mapfd = bpf(BPF_MAP_CREATE, &attr);
  if (mapfd == -1) fatal("bpf(BPF_MAP_CREATE)");
  return mapfd;
}

int map_update(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)pval,
    .flags  = BPF_ANY
  };
  int res = bpf(BPF_MAP_UPDATE_ELEM, &attr);
  if (res == -1) fatal("bpf(BPF_MAP_UPDATE_ELEM)");
  return res;
}

int map_lookup(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)pval,
    .flags  = BPF_ANY
  };
  return bpf(BPF_MAP_LOOKUP_ELEM, &attr); // -1이면 미발견
}


void execute_bpf(mapfd){
  // BPF program for managing map
  struct bpf_insn prog[] = {
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 1),      // key=1
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1337), // val=0x1337
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),

    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)

    BPF_MOV64_IMM(BPF_REG_0, -1),
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
  int prog_fd = bpf(BPF_PROG_LOAD, &attr);
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


  
  const char *msgs[] = {      
      "hi"
  };
  for (int i = 0; i < 1; i++) {
      write(sv[1], msgs[i], strlen(msgs[i]));
      char buf[64] = {};
      int n = read(sv[0], buf, sizeof(buf));
      printf("[%s] read returned %d,", msgs[i], n);
      if (n > 0) printf(" data='%.*s'", n, buf);
      printf("\n");
  }
}

int main(void) {


  /* init map*/
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeefcafebabe;
  map_update(mapfd, 1, &val);

  val = 0;
  map_lookup(mapfd, 1, &val);
  
  // deadbeefcafebabe
  printf("0x%lx\n", val);



  execute_bpf(mapfd);


  // After bpf
  map_lookup(mapfd, 1, &val);

  //1337
  printf("0x%lx\n", val);

  return 0;
}
