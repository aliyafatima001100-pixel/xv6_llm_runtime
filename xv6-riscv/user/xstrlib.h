/**
 * @file xstrlib.h
 * @brief Minimal user-space string utilities for xv6
 */

#ifndef XV6_XSTRLIB_H
#define XV6_XSTRLIB_H

#include "../kernel/types.h"

/* Character classification */
int xisprint(int c);
int xisspace(int c);

/* Formatted output */
int xsprintf(char *out, const char *fmt, ...);
int xsnprintf(char *out, int size, const char *fmt, ...);
int xvsnprintf(char *out, int size, const char *fmt, va_list ap);

/* Formatted input */
int xsscanf(const char *s, const char *fmt, ...);

#endif
