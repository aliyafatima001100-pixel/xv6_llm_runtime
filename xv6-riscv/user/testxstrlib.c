#include "../kernel/types.h"
#include "user.h"
#include <stdarg.h>

// ANSI color escape sequences for nicer output
#define GREEN "\033[1;32m"
#define RESET "\033[0m"

void test_xisprint_xisspace() {
  printf("Testing xisprint/xisspace...\n");

  int pass = 0, total = 2;

  if (xisprint('A') == 1) {
    printf(GREEN "PASS" RESET ": xisprint('A') = 1\n");
    pass++;
  } 
  else {
    printf("FAIL: xisprint('A')\n");
  }

  if (xisspace(' ') == 1) {
    printf(GREEN "PASS" RESET ": xisspace(' ') = 1\n");
    pass++;
  } 
  else {
    printf("FAIL: xisspace(' ')\n");
  }

  printf("xisprint/xisspace tests passed (%d/%d)\n\n", pass, total);
}

void test_xsprintf() {
  printf("Testing xsprintf...\n");
  char buf[128];
  xsprintf(buf, "hello %s %d [float] %%", "world", 42);
  int len = strlen(buf);
  
  // expected string literal (explicit)
  const char *expected = "hello world 42 [float] %";
  int pass = 0, total = 2;

  if (strcmp(buf, expected) == 0) {
    printf(GREEN "PASS" RESET ": Correctly formatted integer, string, and placeholder float\n");
    pass++;
  } 
  else {
    printf("FAIL: Unexpected xsprintf output: %s\n", buf);
  }

  if (len == strlen(expected)) {
    printf(GREEN "PASS" RESET ": Buffer length is correct (%d)\n", len);
    pass++;
  } else {
    printf("FAIL: Buffer length = %d, expected %d\n", len, (int)strlen(expected));
  }

  // Test xsprintf with float
  double f = 3.14159;
  xsprintf(buf, "pi=%.2f", f);
  if (strcmp(buf, "pi=3.14") == 0)
    printf(GREEN "PASS" RESET ": xsprintf(%%.2f) correctly formatted\n");
  else
    printf("FAIL: xsprintf(%%.2f) output = %s\n", buf);

  printf("xsprintf tests passed (%d/%d)\n\n", pass, total);
}

void test_xsscanf() {
  printf("Testing xsscanf...\n");

  int pass = 0, total = 3;

  char hex_input[] = "<0x1F>";
  unsigned int hex_val = 0;
  if (xsscanf(hex_input, "<0x%02X>", &hex_val) == 1 && hex_val == 31) {
    printf(GREEN "PASS" RESET ": Parsed hex correctly (<0x1F> -> 31)\n");
    pass++;
  } 
  else {
    printf("FAIL: xsscanf hex parse\n");
  }

  char int_input[] = "123";
  int i = 0;
  if (xsscanf(int_input, "%d", &i) == 1 && i == 123) {
    printf(GREEN "PASS" RESET ": Parsed integer correctly (123)\n");
    pass++;
  } 
  else {
    printf("FAIL: xsscanf integer parse\n");
  }

  // Test xsscanf with float
  double f = 0.0;
  int matched = xsscanf("2.718", "%f", &f);
  if (matched == 1 && (f > 2.717 && f < 2.719)) {
    printf(GREEN "PASS" RESET ": xsscanf(%%f) correctly parsed 2.718\n");
  }
  else {
    printf("FAIL: xsscanf(%%f) value = %f (matched=%d)\n", f, matched);
  }

  printf("xsscanf tests passed (%d/%d)\n\n", pass, total);
}

int main() {
  printf("Testing xsprintf, xsscanf, xisprint, xisspace...\n\n");

  test_xisprint_xisspace();
  test_xsprintf();
  test_xsscanf();

  
  printf(GREEN "ALL string utilities tests completed successfully!\n" RESET);
  exit(0);
}

