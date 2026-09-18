/**
 * @file xstdlib.h
 * @brief Minimal standard library extensions for xv6 user programs.
 * 
 * @author Hadiya Muneeb
 * @date 9th November 2025
 *
 * @details
 * Provides safe memory allocation, basic numeric conversions, and
 * general-purpose sorting and searching routines usable in xv6 userland.
 * 
 * Functions declared here include:
 *  - xcalloc: zero-initialized allocation with overflow protection
 *  - xbsearch: binary search on a sorted array
 *  - xqsort: quicksort using Hoare partition scheme
 *  - xatoi, xatof: ASCII to integer/float conversions
 */

#ifndef XSTDLIB_H
#define XSTDLIB_H

#include "kernel/types.h"

/**
 * @brief Allocate and zero-initialize an array.
 * @param num  Number of elements.
 * @param size Size of each element in bytes.
 * @return Pointer to zeroed memory, or NULL on failure or overflow.
 */
void* xcalloc(uint num, uint size);

/**
 * @brief Perform binary search on a sorted array.
 * @param key     Pointer to search key.
 * @param base    Pointer to base of array.
 * @param num     Number of elements.
 * @param size    Size of each element in bytes.
 * @param compar  Comparison function: returns <0, 0, >0.
 * @return Pointer to found element or NULL if not found.
 */
void* xbsearch(const void* key, const void* base, uint num, uint size, int (*compar)(const void*, const void*));

/**
 * @brief Sort array using quicksort.
 * @param base   Pointer to array base.
 * @param num    Number of elements.
 * @param size   Size of each element.
 * @param compar Comparison callback.
 */
void xqsort(void* base, uint num, uint size, int (*compar)(const void*, const void*));

/**
 * @brief Convert string to integer.
 * @param str Null-terminated string.
 * @return Parsed integer value, or 0 on invalid input.
 */
int xatoi(const char* str);

/**
 * @brief Convert string to floating-point number.
 * @param str Null-terminated string.
 * @return Parsed double value, or 0.0 on invalid input.
 */
double xatof(const char* str);

#endif // XSTDLIB_H
