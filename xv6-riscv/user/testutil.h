/**
 * @file testutil.h
 * @brief Function declarations for color-coded, indented test output utilities in xv6 userland.
 *
 * @author Syed Taha
 * @date 9th November 2025
 *
 * @details
 * Declares helper functions for consistent colored and indented test output across xv6 userland
 * test programs. Each function prints a formatted line with optional indentation, a globally-set
 * color-coded tag, and a message using ANSI escape sequences.
 *
 * Colors used:
 *  - Red: Failure
 *  - Green: Success
 *  - Yellow: Warning
 *  - Purple: Information
 *
 * The xv6 console must support ANSI escape codes for colors to display correctly.
 */

#ifndef TESTUTIL_H
#define TESTUTIL_H

 /**
  * @brief Set the global tag for subsequent test messages.
  * @param tag Null-terminated string to use as the tag (e.g., "FPUPASS").
  */
void set_tag(const char* tag);

/**
 * @brief Print a failure message (in red) and exit with code 1.
 * @param msg Null-terminated description string.
 * @param ... Additional format arguments (printf-style).
 */
void fail(const char* msg, ...);

/**
 * @brief Print a failure message (in red) without exiting.
 *
 * @param msg Null-terminated description string.
 * @param ... Additional format arguments (printf-style).
 */
void failnoex(const char* msg, ...);


/**
 * @brief Print a success message (in green).
 * @param msg Null-terminated description string.
 * @param ... Additional format arguments (printf-style).
 */
void pass(const char* msg, ...);

/**
 * @brief Print a warning message (in yellow).
 * @param msg Null-terminated description string.
 * @param ... Additional format arguments (printf-style).
 */
void warn(const char* msg, ...);

/**
 * @brief Print an informational message (in purple).
 * @param msg Null-terminated description string.
 * @param ... Additional format arguments (printf-style).
 */
void info(const char* msg, ...);

/**
 * @brief Print a summary of test results.
 * @param passed Number of tests passed.
 * @param total Total number of tests run.
 * @return 0 on success. (all tests passed), 1 if any tests failed.
 */
int summary(int passed, int total);


#endif // TESTUTIL_H
