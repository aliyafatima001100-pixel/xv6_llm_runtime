// test_recvtimeo.c
//
// Two-instance test for sys_recvtimeo() using the real e1000 + bridge
// path (qemu-node1 <-> tap1 <-> br0 <-> tap2 <-> qemu-node2).
//
// Run as a receiver on one node and a sender on the other:
//   qemu-node1 (10.0.0.2):  test_recvtimeo r
//   qemu-node2 (10.0.0.3):  test_recvtimeo s
//
// Start the receiver first - it blocks in recvtimeo() until the
// timeout or until the sender's packet arrives.

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define TEST_PORT     6000
#define SEND_SRC_PORT 6001
#define TICK_HZ       10        // xv6-riscv stock default; confirm this
#define BUFLEN        512

// Hardcoded node IPs (match XV6_IP_D=2 / XV6_IP_D=3 in the Makefile)
#define NODE1_IP  0x0a000002    // 10.0.0.2 - receiver
#define NODE2_IP  0x0a000003    // 10.0.0.3 - sender (unused directly, kept for clarity)

// Mirror whatever sentinel convention you land on in sys_recvtimeo.
// -2 = timeout, -1 = other error, >=0 = bytes received.
#define RECVTIMEO_TIMEOUT (-2)

static int
ms_to_ticks(int ms)
{
  return (ms * TICK_HZ) / 1000;
}

static void
check(const char *name, int cond)
{
  if (cond) {
    printf("[PASS] %s\n", name);
  } else {
    printf("[FAIL] %s\n", name);
  }
}

// Receiver side: binds TEST_PORT and blocks in recvtimeo(),
// waiting for a packet sent from the other node.
static void
run_receiver(void)
{
  uint8 buf[BUFLEN];
  uint32 src_ip;
  uint16 src_port;

  int fd = bind(TEST_PORT);
  if (fd < 0) {
    printf("[FAIL] receiver: bind() failed\n");
    return;
  }

  int timeout_ticks = ms_to_ticks(5000); // generous window to start the sender manually
  printf("receiver: waiting on port %d for %d ticks...\n", TEST_PORT, timeout_ticks);

  int n = recvtimeo(TEST_PORT, &src_ip, &src_port, (char *)buf, BUFLEN, timeout_ticks);

  printf("  -> recvtimeo returned %d (expected 5)\n", n);
  check("packet arrives before timeout", n == 5);
  if (n == 5) {
    buf[5] = 0;
    check("payload matches", strcmp((char *)buf, "hello") == 0);
    printf("  -> src_ip=0x%x src_port=%d\n", src_ip, src_port);
  }

  unbind(TEST_PORT);
}

// Sender side: sends one UDP packet to NODE1_IP:TEST_PORT.
static void
run_sender(void)
{
  const char *msg = "hello";

  int fd = bind(SEND_SRC_PORT);
  if (fd < 0) {
    printf("[FAIL] sender: bind() failed\n");
    return;
  }

  // NOTE: sys_send returns 0 on success (not bytes-sent), -1 on
  // failure. Confirmed against the kernel implementation - this is
  // not a bug, just doesn't mirror POSIX send() semantics.
  int sent = send(fd, NODE1_IP, TEST_PORT, (char *)msg, 5);
  printf("  -> send() returned %d (0 == success for this kernel)\n", sent);
  check("send() reports success", sent == 0);

  unbind(SEND_SRC_PORT);
}

int
main(int argc, char *argv[])
{
  if (argc < 2 || (argv[1][0] != 'r' && argv[1][0] != 's') || argv[1][1] != '\0') {
    printf("usage: %s r|s\n", argv[0]);
    printf("  r = receiver (run on qemu-node1 / 10.0.0.2)\n");
    printf("  s = sender   (run on qemu-node2 / 10.0.0.3)\n");
    exit(1);
  }

  printf("=== recvtimeo tests (%s) ===\n", argv[1][0] == 'r' ? "receiver" : "sender");

  if (argv[1][0] == 'r') {
    run_receiver();
  } else {
    run_sender();
  }

  printf("=== done ===\n");
  exit(0);
}