/**
 * @file xstdlib.c
 * @brief Minimal standard library extensions for xv6 user programs.
 * 
 * @author Hadiya Muneeb
 * @date 9th November 2025
 *
 * @details
 * Implements safe memory allocation, basic numeric conversions, and
 * general-purpose sorting and searching routines usable in xv6 userland.
 * Function-level documentation is provided in the header `xstdlib.h`.
 */

#include "kernel/types.h"
#include "user/user.h"
#include "user/xstdlib.h"

void* xcalloc(uint num, uint size) {
    if (size != 0 && num > (uint)-1 / size) return 0;
    uint total_size = num * size;
    void* ptr = malloc(total_size);
    if (ptr) memset(ptr, 0, total_size);
    return ptr;
}

void* xbsearch(const void* key, const void* base, uint nmemb, uint size, int (*compar)(const void*, const void*)) {
    if (nmemb == 0) return 0;
    const char* low = (const char*)base;
    const char* high = low + (nmemb - 1) * size;

    while (low <= high) {
        int mid_offset = ((high - low) / size) / 2;
        const char* mid_ptr = low + mid_offset * size;
        int cmp = compar(key, mid_ptr);
        if (cmp == 0) return (void*)mid_ptr;
        else if (cmp < 0) high = mid_ptr - size;
        else low = mid_ptr + size;
    }
    return 0;
}

static void swap(char* a, char* b, uint size) {
    for (int i = 0; i < size; i++) {
        char tmp = a[i]; 
        a[i] = b[i]; 
        b[i] = tmp;
    }
}

#define MAX_STACK 128  // log2(vocab_size) * 2 should be enough

void xqsort(void* base, uint nmemb, uint size, int (*compar)(const void*, const void*)) {
    if (nmemb <= 1) return;
    
    // Allocate stack for iterative quicksort
    int* stack = malloc(MAX_STACK * sizeof(int));
    if (!stack) return;
    
    char* arr = (char*)base;
    int top = -1;
    
    // Push initial range
    stack[++top] = 0;
    stack[++top] = nmemb - 1;
    
    while (top >= 0) {
        // Pop range
        int high = stack[top--];
        int low = stack[top--];
        
        if (low >= high) continue;
        
        // Partition
        char* pivot_value = malloc(size);
        if (!pivot_value) {
            free(stack);
            return;
        }
        memcpy(pivot_value, arr + high * size, size);
        
        int i = low - 1;
        for (int j = low; j < high; j++) {
            if (compar(arr + j * size, pivot_value) <= 0) {
                i++;
                swap(arr + i * size, arr + j * size, size);
            }
        }
        swap(arr + (i + 1) * size, arr + high * size, size);
        free(pivot_value);
        
        int p = i + 1;
        
        // Push larger partition first (to minimize stack usage)
        if (p - low > high - p) {
            // Left is larger
            if (low < p - 1) {
                stack[++top] = low;
                stack[++top] = p - 1;
            }
            if (p + 1 < high) {
                stack[++top] = p + 1;
                stack[++top] = high;
            }
        } else {
            // Right is larger
            if (p + 1 < high) {
                stack[++top] = p + 1;
                stack[++top] = high;
            }
            if (low < p - 1) {
                stack[++top] = low;
                stack[++top] = p - 1;
            }
        }
    }
    
    free(stack);
}

int xatoi(const char* str) {
    if (!str) return 0;
    int result = 0, sign = 1;
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') str++;
    if (*str == '+') str++;
    else if (*str == '-') { sign = -1; str++; }
    while (*str >= '0' && *str <= '9') { result = result * 10 + (*str - '0'); str++; }
    return sign * result;
}

static double xpowf(double base, int exponent) {
    if (exponent == 0) return 1.0f;
    double result = 1.0f;
    int abs_exponent = (exponent < 0) ? -exponent : exponent;
    for (int i = 0; i < abs_exponent; i++) result *= base;
    return (exponent < 0) ? 1.0f / result : result;
}

double xatof(const char* str) {
    if (!str) return 0.0f;
    double result = 0.0f, fraction = 1.0f;
    int exponent = 0, sign = 1, exp_sign = 1;

    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') str++;
    if (*str == '+') str++;
    else if (*str == '-') { sign = -1; str++; }

    while (*str >= '0' && *str <= '9') { result = result * 10.0f + (*str - '0'); str++; }
    if (*str == '.') {
        str++;
        while (*str >= '0' && *str <= '9') { result = result * 10.0f + (*str - '0'); fraction *= 10.0f; str++; }
    }
    result = sign * result / fraction;

    if (*str == 'e' || *str == 'E') {
        str++;
        if (*str == '+') str++;
        else if (*str == '-') { exp_sign = -1; str++; }
        while (*str >= '0' && *str <= '9') { exponent = exponent * 10 + (*str - '0'); str++; }
        if (exponent != 0) result *= xpowf(10.0f, exp_sign * exponent);
    }

    return result;
}
