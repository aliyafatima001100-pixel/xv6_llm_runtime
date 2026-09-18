/**
 * @file testutil.c
 * @brief Implementation of color-coded, indented test output utilities in xv6 userland.
 *
 * @author Syed Taha
 * @date 9th November 2025
 *
 * @details
 * Provides functions for consistent colored and indented test output using a globally-set tag.
 * ANSI escape sequences are used to produce colors on the xv6 console.
 */

#include "kernel/types.h"
#include "user/user.h"
#include "testutil.h"
#include <stdarg.h>

#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_PURPLE  "\033[35m"
#define ANSI_RESET   "\033[0m"

static const char* global_tag = "TEST";

static void vprint_colored(const char* tag, const char* color, const char* fmt, va_list ap) {

  // Print tag if present
  if (tag && tag[0] != '\0') {
    printf("%s%s   ", color, tag);
  }
  else {
    printf("%s", color);
  }

  // Print the formatted message
  vprintf(1, fmt, ap);
  printf("%s\n", ANSI_RESET);
}

void set_tag(const char* tag) {
  global_tag = tag;
}

void fail(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprint_colored("FAIL", ANSI_RED, fmt, ap);
  va_end(ap);
  exit(1);
}

void failnoex(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprint_colored("FAIL", ANSI_RED, fmt, ap);
  va_end(ap);
}

void pass(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprint_colored("PASS", ANSI_GREEN, fmt, ap);
  va_end(ap);
}

void warn(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprint_colored("WARNING", ANSI_YELLOW, fmt, ap);
  va_end(ap);
}

void info(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprint_colored("", ANSI_PURPLE, fmt, ap);
  va_end(ap);
}

int summary(int passed, int total) {
  info("========== %s SUMMARY ==========", global_tag);
  info("        Tests passed: %d / %d", passed, total);
  info("====================================");
  return (passed == total) ? 0 : 1;
}
