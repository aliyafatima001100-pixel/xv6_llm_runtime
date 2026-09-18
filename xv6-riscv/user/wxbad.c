//
// wxbad -- a deliberately W^X-violating binary, used by wxtest.
//
// The Makefile links it into a single OMAGIC R+W+X segment WITHOUT the PT_OPENBSD_WXNEEDED
// exemption tag, so the kernel's W^X enforcement (kernel/exec.c) must refuse to exec it.
// Its body never runs in the test (exec fails first); main() just exits so it is a
// well-formed program.
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(void)
{
  exit(0);
}
