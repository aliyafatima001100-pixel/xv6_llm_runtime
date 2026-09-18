//
// netecho — minimal UDP echo responder for differential network testing.
//
// Binds a UDP port and echoes every received datagram back to its sender. A
// host-side test harness uses the echo to tell "delivered" (an echo comes back)
// apart from "silently dropped" (nothing comes back) when probing the kernel's
// packet validation in ip_rx().
//
//   netecho [port]      (default 2000)
//

#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  uint16 port = 2000;
  if(argc > 1)
    port = atoi(argv[1]);

  if(bind(port) < 0){
    fprintf(2, "netecho: bind(%d) failed\n", port);
    exit(1);
  }

  printf("netecho: listening on UDP port %d\n", port);

  for(;;){
    char buf[2048];
    uint32 src;
    uint16 sport;

    int cc = recv(port, &src, &sport, buf, sizeof(buf));
    if(cc < 0){
      fprintf(2, "netecho: recv() failed\n");
      exit(1);
    }

    // Echo the payload straight back to whoever sent it.
    if(send(port, src, sport, buf, cc) < 0)
      fprintf(2, "netecho: send() failed\n");
  }

  exit(0);
}
