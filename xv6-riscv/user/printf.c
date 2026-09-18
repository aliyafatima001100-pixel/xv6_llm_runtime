#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#include <stdarg.h>

static char digits[] = "0123456789abcdef";

// ----- indentation control -----
static int print_indent_level = 0;

// Set indentation width in spaces
void printf_set_indent(int spaces) {
  if (spaces < 0) spaces = 0;
  print_indent_level = spaces;
}

// Reset indentation to zero
void printf_reset_indent(void) {
  print_indent_level = 0;
}

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
}

static void print_indent(int fd) {
  for (int i = 0; i < print_indent_level; i++)
    putc(fd, ' ');
}

/**
 * @brief Print an integer in a specified base with optional sign and width.
 * 
 * @param fd File descriptor to write to
 * @param xx The integer to print
 * @param base The numerical base (e.g., 10 for decimal, 16 for hex)
 * @param sgn Non-zero if the integer is signed
 * @param width Minimum field width (padded with spaces if necessary)
 */
static void printint(int fd, long long xx, int base, int sgn, int width) {
  char buf[32];
  int i = 0, neg = 0;
  unsigned long long x;

  if(sgn && xx < 0){
    neg = 1;
    x = -xx;
  } else {
    x = xx;
  }

  do {
    buf[i++] = digits[x % base];
  } while((x /= base) != 0);

  if(neg)
    buf[i++] = '-';

  int len = i;
  int pad = width > len ? width - len : 0;

  while(pad-- > 0)
    putc(fd, ' ');

  while(--i >= 0)
    putc(fd, buf[i]);
}


/**
 * @brief Print a double-precision floating-point number with specified width and precision.
 * @param fd File descriptor to write to
 * @param d The double value to print
 * @param width Minimum field width (padded with spaces if necessary)
 * @param prec Number of digits after the decimal point
 */
static void printdouble(int fd, double d, int width, int prec) {
  char buf[64];
  int bi = 0;

  if (d < 0) {
    buf[bi++] = '-';
    d = -d;
  }

  long long intpart = (long long)d;
  double frac = d - (double)intpart;

  // convert integer part
  char ibuf[32];
  int ii = 0;
  unsigned long long x = intpart;
  do {
    ibuf[ii++] = digits[x % 10];
  } while((x /= 10) != 0);

  // append integer reversed
  for (int k = ii - 1; k >= 0; k--)
    buf[bi++] = ibuf[k];

  buf[bi++] = '.';

  // fractional part
  for (int i = 0; i < prec; i++) {
    frac *= 10;
    int digit = (int)frac;
    buf[bi++] = '0' + digit;
    frac -= digit;
  }

  buf[bi] = 0;

  // compute padding
  int len = bi;
  int pad = width > len ? width - len : 0;

  while (pad-- > 0)
    putc(fd, ' ');

  for (int k = 0; k < len; k++)
    putc(fd, buf[k]);
}

static void
printptr(int fd, uint64 x) {
  int i;
  putc(fd, '0');
  putc(fd, 'x');
  for (i = 0; i < (sizeof(uint64) * 2); i++, x <<= 4)
    putc(fd, digits[x >> (sizeof(uint64) * 8 - 4)]);
}

void vprintf(int fd, const char *fmt, va_list ap) {
  char *s;
  int c0, c1, c2, i, state;
  int at_line_start = 1;

  state = 0;
  for(i = 0; fmt[i]; i++){
    c0 = fmt[i] & 0xff;

    if (at_line_start && c0 != '\n') {
      print_indent(fd);
      at_line_start = 0;
    }

    if(state == 0){
      if(c0 == '%'){
        state = '%';
      } else {
        putc(fd, c0);
      }
    } else if(state == '%'){

      c1 = c2 = 0;
      if(c0) c1 = fmt[i+1] & 0xff;
      if(c1) c2 = fmt[i+2] & 0xff;

      // ---- WIDTH + PRECISION FOR FLOATS ----
      int width = 0;
      int prec = -1;
      int j = i;

      // width
      while (fmt[j] >= '0' && fmt[j] <= '9') {
        width = width * 10 + (fmt[j] - '0');
        j++;
      }

      // precision
      if (fmt[j] == '.') {
        j++;
        prec = 0;
        while (fmt[j] >= '0' && fmt[j] <= '9') {
          prec = prec * 10 + (fmt[j] - '0');
          j++;
        }
      }

      if (j != i) {
        c0 = fmt[j] & 0xff;
        c1 = fmt[j+1] & 0xff;
        c2 = fmt[j+2] & 0xff;
        i = j;
      }
      // -------------------------------------

      // integers (width only)
      if(c0 == 'd'){
        printint(fd, va_arg(ap, int), 10, 1, width);
      } else if(c0 == 'l' && c1 == 'd'){
        printint(fd, va_arg(ap, uint64), 10, 1, width);
        i += 1;
      } else if(c0 == 'l' && c1 == 'l' && c2 == 'd'){
        printint(fd, va_arg(ap, uint64), 10, 1, width);
        i += 2;
      } else if(c0 == 'u'){
        printint(fd, va_arg(ap, uint32), 10, 0, width);
      } else if(c0 == 'l' && c1 == 'u'){
        printint(fd, va_arg(ap, uint64), 10, 0, width);
        i += 1;
      } else if(c0 == 'l' && c1 == 'l' && c2 == 'u'){
        printint(fd, va_arg(ap, uint64), 10, 0, width);
        i += 2;
      } else if(c0 == 'x'){
        printint(fd, va_arg(ap, uint32), 16, 0, width);
      } else if(c0 == 'l' && c1 == 'x'){
        printint(fd, va_arg(ap, uint64), 16, 0, width);
        i += 1;
      } else if(c0 == 'l' && c1 == 'l' && c2 == 'x'){
        printint(fd, va_arg(ap, uint64), 16, 0, width);
        i += 2;
      } else if(c0 == 'p'){
        printptr(fd, va_arg(ap, uint64));
      } else if(c0 == 'c'){
        putc(fd, va_arg(ap, uint32));
      } else if(c0 == 's'){
          if((s = va_arg(ap, char*)) == 0) s = "(null)";
          
          // compute string length
          int len = 0;
          for(char *p = s; *p; p++) len++;

          // pad if width > len
          int pad = width > len ? width - len : 0;
          while(pad-- > 0) putc(fd, ' ');

          // print the string
          for(; *s; s++) putc(fd, *s);

      } else if (c0 == 'f') {
        if (prec < 0) prec = 6;
        printdouble(fd, va_arg(ap, double), width, prec);
      } else if(c0 == '%'){
        putc(fd, '%');
      } else {
        // Unknown % sequence.  Print it to draw attention.
        putc(fd, '%');
        putc(fd, c0);
      }

      state = 0;
    }
  }
}

void
fprintf(int fd, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(fd, fmt, ap);
}

void
printf(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(1, fmt, ap);
}
