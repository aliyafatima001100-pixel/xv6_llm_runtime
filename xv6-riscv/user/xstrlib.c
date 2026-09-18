/**
 * @file xstrlib.c
 * @brief user-space string utility implementations for xv6
 *
 * provides small, safe, and self-contained replacements for
 * basic libc-like functions such as `sprintf`, `sscanf`, `isprint`, and `isspace`,
 * implemented for the xv6 user environment
 *
 * Features:
 * - Bounded formatting (`xsnprintf`, `xvsnprintf`, `xsprintf`)
 * - Limited `xsscanf` for `%d`, `%x/%X`, `%f`, `%s`, `%c`
 * - Simple helpers for printable and whitespace checks
 * - Basic float handling (`ftoa`, `round_to_precision`) compatible with FPU-enabled xv6
 *
 * uses xv6 integer types (`uint`) and standard varargs (`<stdarg.h>`).
 */

#include "../kernel/types.h"
#include "user.h"
#include <stdarg.h>

/* ============================================================
 * Character classification
 * ============================================================ */

/**
 * @brief Check if a character is printable (ASCII 0x20–0x7E).
 * @param c Character code.
 * @return 1 if printable, 0 otherwise.
 */
int xisprint(int c) {
  return (c >= 0x20 && c < 0x7f);
}

/**
 * @brief Check if a character is a whitespace.
 * @param c Character code.
 * @return 1 if whitespace (' ', '\f', '\n', '\r', '\t', '\v'), 0 otherwise.
 */
int xisspace(int c) {
  return (c == ' ' || c == '\f' || c == '\n' ||
          c == '\r' || c == '\t' || c == '\v');
}

/* ============================================================
 * Integer to string conversion helpers
 * ============================================================ */

/**
 * @brief Convert unsigned integer to decimal string.
 * @param val Value to convert.
 * @param buf Destination buffer.
 * @param bufsize Buffer size.
 * @return Number of characters written (excluding NUL).
 */
static int utoa_dec(unsigned long long val, char *buf, int bufsize) {
  if (bufsize <= 0) return 0;
  char tmp[32];
  int tp = 0;
  if (val == 0) {
    if (bufsize > 1) { buf[0] = '0'; buf[1] = '\0'; return 1; }
    buf[0] = '\0'; return 0;
  }
  while (val && tp < (int)sizeof(tmp)) {
    tmp[tp++] = '0' + (val % 10);
    val /= 10;
  }
  int out = 0;
  for (int i = tp - 1; i >= 0 && out + 1 < bufsize; --i)
    buf[out++] = tmp[i];
  buf[out] = '\0';
  return out;
}

/**
 * @brief Convert unsigned integer to hexadecimal string.
 * @param val Value to convert.
 * @param buf Destination buffer.
 * @param bufsize Buffer size.
 * @param uppercase Whether to use uppercase letters (A–F).
 * @return Number of characters written (excluding NUL).
 */
static int utoa_hex(unsigned long long val, char *buf, int bufsize, int uppercase) {
  if (bufsize <= 0) return 0;
  char tmp[32];
  int tp = 0;
  if (val == 0) {
    if (bufsize > 1) { buf[0] = '0'; buf[1] = '\0'; return 1; }
    buf[0] = '\0'; return 0;
  }
  while (val && tp < (int)sizeof(tmp)) {
    int d = val & 0xF;
    tmp[tp++] = (d < 10) ? ('0' + d) : ((uppercase ? 'A' : 'a') + (d - 10));
    val >>= 4;
  }
  int out = 0;
  for (int i = tp - 1; i >= 0 && out + 1 < bufsize; --i)
    buf[out++] = tmp[i];
  buf[out] = '\0';
  return out;
}

/* ============================================================
 * Floating-point formatting (ftoa)
 * ============================================================ */

/**
 * @brief Round a floating-point number to a given precision.
 * @param x Input value.
 * @param prec Number of decimal places.
 * @return Rounded floating-point number.
 */
static double round_to_precision(double x, int prec) {
  double p = 1.0;
  for (int i = 0; i < prec; ++i) p *= 10.0;
  if (x >= 0) return (double)((long long)(x * p + 0.5)) / p;
  else return (double)((long long)(x * p - 0.5)) / p;
}

/**
 * @brief Convert a double to string representation with fixed precision.
 * @param val Input value.
 * @param buf Destination buffer.
 * @param bufsize Buffer size.
 * @param prec Decimal precision.
 * @return Number of characters written (excluding NUL).
 */
static int ftoa(double val, char *buf, int bufsize, int prec) {
  if (bufsize <= 0) return 0;
  if (prec < 0) prec = 6;

  if (val != val) { // NaN
    if (bufsize > 3) { memcpy(buf, "nan", 3); buf[3] = '\0'; return 3; }
    return 0;
  }
  if (val == 1.0 / 0.0) { if (bufsize > 3) { memcpy(buf, "inf", 3); buf[3] = '\0'; return 3; } return 0; }
  if (val == -1.0 / 0.0) { if (bufsize > 4) { memcpy(buf, "-inf", 4); buf[4] = '\0'; return 4; } return 0; }

  int pos = 0;
  if (val < 0.0) {
    if (pos + 1 < bufsize) buf[pos++] = '-';
    val = -val;
  }

  val = round_to_precision(val, prec);
  unsigned long long ipart = (unsigned long long)val;
  double frac = val - (double)ipart;

  char intbuf[32];
  int nint = utoa_dec(ipart, intbuf, sizeof(intbuf));
  if (pos + nint + 1 >= bufsize) {
    int copy = bufsize - pos - 1;
    if (copy > 0) memcpy(buf + pos, intbuf, copy);
    buf[pos] = '\0';
    return pos;
  }
  memcpy(buf + pos, intbuf, nint);
  pos += nint;

  if (prec == 0) { buf[pos] = '\0'; return pos; }
  if (pos + 1 >= bufsize) { buf[pos] = '\0'; return pos; }

  buf[pos++] = '.';
  for (int i = 0; i < prec; ++i) {
    frac *= 10.0;
    int d = (int)frac;
    if (pos + 1 >= bufsize) break;
    buf[pos++] = '0' + d;
    frac -= d;
  }
  buf[pos] = '\0';
  return pos;
}

/* ============================================================
 * Formatted output: vsnprintf / snprintf / sprintf
 * ============================================================ */

/**
 * @brief Bounded vsnprintf for xv6 (safe, small implementation)
 * @param out Output buffer
 * @param size Maximum size (including NULL)
 * @param fmt Format string (%d, %s, %f, %x/%X, %c, %%)
 * @param ap Varargs list
 * @return Number of characters written (excluding NULL)
 */
int xvsnprintf(char *out, int size, const char *fmt, va_list ap) {
  if (size <= 0) return 0;
  int outpos = 0;
  const char *p = fmt;
  while (*p) {
    if (*p != '%') {
      if (outpos + 1 < size) out[outpos++] = *p;
      ++p;
      continue;
    }
    p++;
    int precision = -1;
    if (*p == '.') {
      p++;
      int v = 0;
      while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
      precision = v;
    }
    char spec = *p++;
    if (spec == '%') {
      if (outpos + 1 < size) out[outpos++] = '%';
    } else if (spec == 'd') {
      int v = va_arg(ap, int);
      unsigned int uv = (v < 0) ? (unsigned int)(- (long long)v) : (unsigned int)v;
      char tmp[32];
      int n = utoa_dec(uv, tmp, sizeof(tmp));
      if (v < 0 && outpos + 1 < size) out[outpos++] = '-';
      for (int i = 0; i < n && outpos + 1 < size; ++i) out[outpos++] = tmp[i];
    } else if (spec == 's') {
      char *s = va_arg(ap, char*);
      if (!s) s = "(null)";
      for (int i = 0; s[i] && outpos + 1 < size; ++i) out[outpos++] = s[i];
    } else if (spec == 'c') {
      int ch = va_arg(ap, int);
      if (outpos + 1 < size) out[outpos++] = (char)ch;
    } else if (spec == 'f') {
      double fv = va_arg(ap, double);
      char tmp[64];
      int used = ftoa(fv, tmp, sizeof(tmp), precision >= 0 ? precision : 6);
      for (int i = 0; i < used && outpos + 1 < size; ++i) out[outpos++] = tmp[i];
    } else if (spec == 'x' || spec == 'X') {
      unsigned int uv = va_arg(ap, unsigned int);
      char tmp[32];
      int used = utoa_hex(uv, tmp, sizeof(tmp), spec == 'X');
      for (int i = 0; i < used && outpos + 1 < size; ++i) out[outpos++] = tmp[i];
    } else {
      if (outpos + 1 < size) out[outpos++] = '%';
      if (outpos + 1 < size) out[outpos++] = spec;
    }
  }
  out[outpos] = '\0';
  return outpos;
}

/**
 * @brief Safe snprintf variant
 * @param out Output buffer
 * @param size Buffer size
 * @param fmt Format string
 * @return Number of characters written
 */
int xsnprintf(char *out, int size, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int r = xvsnprintf(out, size, fmt, ap);
  va_end(ap);
  return r;
}

/**
 * @brief Simplified sprintf wrapper (bounded internally to 1024)
 * @param out Output buffer
 * @param fmt Format string
 * @return Number of characters written
 */
int xsprintf(char *out, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int r = xvsnprintf(out, 1024, fmt, ap);
  if (r >= 1024) out[1023] = '\0';
  va_end(ap);
  return r;
}

/* ============================================================
 * Formatted input: sscanf
 * ============================================================ */

/**
 * @brief Minimal sscanf implementation
 *
 * Supports parsing of `%d`, `%f`, `%s`, `%c`, and `%x/%X`
 * Ignores unsupported length modifiers (`hh`, `l`, etc.)
 *
 * @param s Input string
 * @param fmt Format string
 * @return Number of successful assignments
 */
int xsscanf(const char *s, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int assigned = 0;
  const char *ps = s;
  const char *pf = fmt;

  while (*pf) {
    if (*pf == '%') {
      pf++;
      if (*pf == 'h') { pf++; if (*pf == 'h') pf++; }
      while (*pf >= '0' && *pf <= '9') pf++;
      char spec = *pf++;
      while (*ps && xisspace((int)*ps)) ps++;

      if (spec == 'd') {
        int sign = 1; long val = 0;
        if (*ps == '-') { sign = -1; ps++; }
        if (*ps < '0' || *ps > '9') break;
        while (*ps >= '0' && *ps <= '9') { val = val * 10 + (*ps - '0'); ps++; }
        int *ip = va_arg(ap, int*);
        *ip = (int)(val * sign);
        assigned++;
      } else if (spec == 'f') {
        int sign = 1; double val = 0.0;
        if (*ps == '-') { sign = -1; ps++; }
        if (!(*ps >= '0' && *ps <= '9')) break;
        while (*ps >= '0' && *ps <= '9') { val = val * 10.0 + (*ps - '0'); ps++; }
        if (*ps == '.') {
          ps++;
          double place = 0.1;
          while (*ps >= '0' && *ps <= '9') {
            val += (*ps - '0') * place;
            place *= 0.1;
            ps++;
          }
        }
        double *fp = va_arg(ap, double*);
        *fp = val * sign;
        assigned++;
      } else if (spec == 's') {
        char *dest = va_arg(ap, char*);
        if (!dest) break;
        while (*ps && !xisspace((int)*ps)) { *dest++ = *ps++; }
        *dest = '\0';
        assigned++;
      } else if (spec == 'c') {
        char *cp = va_arg(ap, char*);
        *cp = *ps ? *ps++ : '\0';
        assigned++;
      } else if (spec == 'x' || spec == 'X') {
        unsigned int val = 0; int got = 0;
        while ((*ps >= '0' && *ps <= '9') ||
               (*ps >= 'a' && *ps <= 'f') ||
               (*ps >= 'A' && *ps <= 'F')) {
          got = 1;
          int digit;
          if (*ps >= '0' && *ps <= '9') digit = *ps - '0';
          else if (*ps >= 'a' && *ps <= 'f') digit = 10 + (*ps - 'a');
          else digit = 10 + (*ps - 'A');
          val = (val << 4) | (unsigned int)digit;
          ps++;
        }
        if (!got) break;
        unsigned int *up = va_arg(ap, unsigned int*);
        *up = val;
        assigned++;
      } else break;
    } else {
      if (*pf == *ps) { pf++; ps++; }
      else break;
    }
    while (*pf == ' ') pf++;
  }

  va_end(ap);
  return assigned;
}

