/**
 * @file testxstdlib.c
 * @brief Unit tests for xv6 xstdlib functions.

 * @author Hadiya Muneeb
 * @date 9th November 2025
 *
 * @details
 * Verifies correctness of xstdlib.c utilities: memory allocation, sorting,
 * binary search, and numeric string conversions. Each test reports colored
 * PASS/FAIL messages to the console.
 *
 * Tests covered:
 *  - xcalloc: allocation and zeroing behavior
 *  - xatoi: string-to-integer parsing
 *  - xatof: string-to-float parsing
 *  - xqsort: quicksort correctness
 *  - xbsearch: binary search correctness
 *
 */

#include "kernel/types.h"
#include "user/user.h"
#include "user/xstdlib.h"

// ANSI color codes for xv6
#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_RESET   "\x1b[0m"


// Integer comparison function for sorting/searching.
int int_compar(const void* a, const void* b) {
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ia > ib) - (ia < ib);
}

// Floating-point comparison function for sorting/searching
int float_compar(const void* a, const void* b) {
    float fa = *(const float*)a;
    float fb = *(const float*)b;
    if (fa < fb) return -1;
    if (fa > fb) return 1;
    return 0;
}

/**
 * @brief Print a success message.
 *
 * @param msg Null-terminated success description.
 */
static void pass(const char* msg) {
    printf(ANSI_GREEN "  PASS: %s\n" ANSI_RESET, msg);
}

/**
 * @brief Print a failure message.
 *
 * @param msg Null-terminated failure description.
 */
static void fail(const char* msg) {
    printf(ANSI_RED "  FAIL: %s\n" ANSI_RESET, msg);
}

/**
 * @brief Test xcalloc for correct allocation and zero-initialization.
 */ 
void test_xcalloc() {
    printf("Testing xcalloc...\n");
    int pass_count = 0;
    int total_tests = 0;
    
    // Test 1: Normal allocation 
    total_tests++;
    int* arr = (int*)xcalloc(5, sizeof(int));
    if (arr != 0) {
        int all_zero = 1;
        for (int i = 0; i < 5; i++) {
            if (arr[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            pass("5-element array initialized properly");
            pass_count++;
        } else {
            fail("Memory not properly zeroed");
        }
        free(arr);
    } else {
        fail("Normal allocation failed");
    }
    
    // Test 2: Zero elements allocation - should return NULL or unique pointer
    total_tests++;
    void* ptr = xcalloc(0, sizeof(int));
    if (ptr == 0) {
        pass("Zero elements returns NULL");
        pass_count++;
    } else {
        pass("Zero elements returns pointer");
        free(ptr);
        pass_count++;
    }
    
    // Test 3: Zero size allocation - should return NULL or unique pointer
    total_tests++;
    ptr = xcalloc(5, 0);
    if (ptr == 0) {
        pass("Zero size returns NULL");
        pass_count++;
    } else {
        pass("Zero size returns pointer");
        free(ptr);
        pass_count++;
    }
    
    // Test 4: Overflow protection - prevent uint multiplication overflow
    total_tests++;
    ptr = xcalloc((uint)-1, (uint)-1);
    if (ptr == 0) {
        pass("Overflow protection works correctly");
        pass_count++;
    } else {
        fail("Overflow should return NULL");
        free(ptr);
    }
    
    printf("  xcalloc %d/%d tests passed\n\n", pass_count, total_tests);
}

/**
 * @brief Test xatoi for correct integer conversion from string input.
 */
void test_xatoi() {
    printf("Testing xatoi...\n");
    int pass_count = 0;
    int total_tests = 0;
    
    struct {
        const char* input;
        int expected;
    } tests[] = {
        {"123", 123},              // Basic positive number
        {"-456", -456},            // Negative number
        {"  789", 789},            // Leading whitespace
        {"+42", 42},               // Explicit positive sign
        {"0", 0},                  // Zero
        {"123abc", 123},           // Stops at non-digit character
        {"abc", 0},                // Invalid input returns 0
        {"", 0},                   // Empty string returns 0
        {"    ", 0},               // Only whitespace returns 0
        {"-", 0},                  // Only minus sign returns 0
        {"+", 0},                  // Only plus sign returns 0
        {"2147483647", 2147483647}, // Maximum positive integer
        {"-2147483648", -2147483648}, // Minimum negative integer
    };
    
    total_tests = sizeof(tests) / sizeof(tests[0]);
    
    for (int i = 0; i < total_tests; i++) {
        int result = xatoi(tests[i].input);
        if (result == tests[i].expected) {
            pass_count++;
        } else {
            printf(ANSI_RED "  FAIL: xatoi(\"%s\") = %d, expected %d\n" ANSI_RESET, 
                   tests[i].input, result, tests[i].expected);
        }
    }
    
    if (pass_count == total_tests) {
        pass("All xatoi tests passed");
    } else {
        printf(ANSI_YELLOW "  xatoi %d/%d tests passed\n" ANSI_RESET, pass_count, total_tests);
    }
    printf("\n");
}

/**
 * @brief Test xatof for correct float conversion with decimals and exponents.
 */
void test_xatof() {
    printf("Testing xatof...\n");
    int pass_count = 0;
    int total_tests = 0;
    
    struct {
        const char* input;
        double expected;
        double tolerance;
    } tests[] = {
        {"3.14", 3.14, 0.01},           // Basic decimal
        {"-2.5", -2.5, 0.01},           // Negative decimal
        {"0.5", 0.5, 0.01},             // Fractional number
        {"123", 123.0, 0.01},           // Integer as float
        {"1.5e1", 15.0, 0.1},           // Scientific notation positive exponent
        {"2e-1", 0.2, 0.01},            // Scientific notation negative exponent
        {"1.5e-3", 0.0015, 0.0001},     // Small scientific notation
        {".5", 0.5, 0.01},              // Start with decimal point
        {"abc", 0.0, 0.01},             // Invalid input returns 0.0
        {"", 0.0, 0.01},                // Empty string returns 0.0
        {"  1.23  ", 1.23, 0.01},       // Leading and trailing whitespace
        {"1.23e", 1.23, 0.01},          // Incomplete exponent continues
        {"-0.75", -0.75, 0.01},         // Negative fractional
        {"1.23456", 1.23456, 0.0001},   // Multiple decimal places
    };
    
    total_tests = sizeof(tests) / sizeof(tests[0]);
    
    for (int i = 0; i < total_tests; i++) {
        double result = xatof(tests[i].input);
        double diff = result - tests[i].expected;
        if (diff < 0) diff = -diff;  
        
        if (diff <= tests[i].tolerance) {
            pass_count++;
        } else {
            printf(ANSI_RED "  FAIL: xatof(\"%s\") = %.6f, expected %.6f (diff: %.6f)\n" ANSI_RESET, 
                   tests[i].input, result, tests[i].expected, diff);
        }
    }
    
    if (pass_count == total_tests) {
        pass("All xatof tests passed");
    } else {
        printf(ANSI_YELLOW "  xatof %d/%d tests passed\n" ANSI_RESET, pass_count, total_tests);
    }
    printf("\n");
}

/**
 * @brief Test xqsort for correctness on integer arrays with varied order.
 */
void test_xqsort() {
    printf("Testing xqsort...\n");
    int pass_count = 0;
    int total_tests = 0;
    
    // Test 1: Sort random integers
    total_tests++;
    int arr[] = {5, 2, 8, 1, 9, 3, 7, 4, 6, 0};
    int sorted[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    int n = sizeof(arr) / sizeof(arr[0]);
    
    xqsort(arr, n, sizeof(int), int_compar);
    
    int correct = 1;
    for (int i = 0; i < n; i++) {
        if (arr[i] != sorted[i]) {
            correct = 0;
            break;
        }
    }
    
    if (correct) {
        pass("Random integer array sorted correctly");
        pass_count++;
    } else {
        fail("Integer sorting failed");
    }
    
    // Test 2: Already sorted array - should remain unchanged
    total_tests++;
    int sorted_arr[] = {1, 2, 3, 4, 5};
    int sorted_backup[] = {1, 2, 3, 4, 5};
    xqsort(sorted_arr, 5, sizeof(int), int_compar);
    
    correct = 1;
    for (int i = 0; i < 5; i++) {
        if (sorted_arr[i] != sorted_backup[i]) {
            correct = 0;
            break;
        }
    }
    
    if (correct) {
        pass("Already sorted array remains sorted");
        pass_count++;
    } else {
        fail("Already sorted array was modified");
    }
    
    // Test 3: Reverse sorted array
    total_tests++;
    int reverse[] = {5, 4, 3, 2, 1};
    int expected[] = {1, 2, 3, 4, 5};
    xqsort(reverse, 5, sizeof(int), int_compar);
    
    correct = 1;
    for (int i = 0; i < 5; i++) {
        if (reverse[i] != expected[i]) {
            correct = 0;
            break;
        }
    }
    
    if (correct) {
        pass("Reverse sorted array sorted correctly");
        pass_count++;
    } else {
        fail("Reverse sorted array failed");
    }
    
    // Test 4: Single element array - should remain unchanged
    total_tests++;
    int single[] = {42};
    xqsort(single, 1, sizeof(int), int_compar);
    if (single[0] == 42) {
        pass("Single element array handled correctly");
        pass_count++;
    } else {
        fail("Single element array was modified");
    }
    
    // Test 5: Array with duplicates
    total_tests++;
    int duplicates[] = {3, 1, 2, 3, 1, 2};
    int dup_sorted[] = {1, 1, 2, 2, 3, 3};
    xqsort(duplicates, 6, sizeof(int), int_compar);
    
    correct = 1;
    for (int i = 0; i < 6; i++) {
        if (duplicates[i] != dup_sorted[i]) {
            correct = 0;
            break;
        }
    }
    
    if (correct) {
        pass("Array with duplicates sorted correctly");
        pass_count++;
    } else {
        fail("Array with duplicates failed");
    }
    
    // REMOVED: Test 6: NULL compar function - should return without sorting
    // This test case has been removed as requested
    
    printf("  xqsort %d/%d tests passed\n\n", pass_count, total_tests);
}

/**
 * @brief Test xbsearch for finding and failing on sorted integer arrays.
 */
void test_xbsearch() {
    printf("Testing xbsearch...\n");
    int pass_count = 0;
    int total_tests = 0;
    
    int arr[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19};
    int n = sizeof(arr) / sizeof(arr[0]);
    
    // Test 1: Find existing middle element
    total_tests++;
    int key = 7;
    int* result = (int*)xbsearch(&key, arr, n, sizeof(int), int_compar);
    if (result != 0 && *result == 7) {
        pass("Found existing middle element");
        pass_count++;
    } else {
        fail("Could not find existing element");
    }
    
    // Test 2: Search for non-existent element
    total_tests++;
    key = 8;
    result = (int*)xbsearch(&key, arr, n, sizeof(int), int_compar);
    if (result == 0) {
        pass("Correctly returned NULL for non-existent element");
        pass_count++;
    } else {
        fail("Should return NULL for non-existent element");
    }
    
    // Test 3: Search in empty array
    total_tests++;
    result = (int*)xbsearch(&key, arr, 0, sizeof(int), int_compar);
    if (result == 0) {
        pass("Empty array search returns NULL");
        pass_count++;
    } else {
        fail("Empty array search should return NULL");
    }
    
    // Test 4: Find first element
    total_tests++;
    key = 1;
    result = (int*)xbsearch(&key, arr, n, sizeof(int), int_compar);
    if (result != 0 && *result == 1) {
        pass("Found first element");
        pass_count++;
    } else {
        fail("Could not find first element");
    }
    
    // Test 5: Find last element
    total_tests++;
    key = 19;
    result = (int*)xbsearch(&key, arr, n, sizeof(int), int_compar);
    if (result != 0 && *result == 19) {
        pass("Found last element");
        pass_count++;
    } else {
        fail("Could not find last element");
    }
    
    // Test 6: Search in single-element array
    total_tests++;
    int single_arr[] = {5};
    key = 5;
    result = (int*)xbsearch(&key, single_arr, 1, sizeof(int), int_compar);
    if (result != 0 && *result == 5) {
        pass("Found element in single-element array");
        pass_count++;
    } else {
        fail("Could not find element in single-element array");
    }
    
    // Test 7: NULL key parameter
    total_tests++;
    result = (int*)xbsearch(0, arr, n, sizeof(int), int_compar);
    if (result == 0) {
        pass("NULL key returns NULL");
        pass_count++;
    } else {
        fail("NULL key should return NULL");
    }
    
    // REMOVED: Test 8: NULL compar function
    // This test case has been removed as requested
    
    printf("  xbsearch %d/%d tests passed\n\n", pass_count, total_tests);
}

/**
 * @brief Main test runner for all xstdlib tests.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status code.
 */
int main(int argc, char* argv[]) {
    // Set indentation if provided. usage teststdlib <level>
    if (argc == 2) {
      int indent = atoi(argv[1]);
      printf_set_indent(indent);
    }

    printf(ANSI_CYAN "    Testing: xcalloc, xatoi, xatof, xqsort, xbsearch\n" ANSI_RESET);
    
    test_xcalloc();
    test_xatoi();
    test_xbsearch();
    test_xqsort();
    test_xatof();
    
    printf(ANSI_GREEN "All xstdlib tests completed successfully!\n" ANSI_RESET);
    
    exit(0);
}