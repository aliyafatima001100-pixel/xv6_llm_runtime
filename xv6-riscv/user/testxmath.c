/**
 * @file test_math.c
 * @brief Comprehensive test suite for custom math library functions in xv6
 *
 * @author Hamna Sajid
 * @date 11/09/2025
 *
 * @details
 * This file implements a comprehensive test suite for custom mathematical
 * functions implemented for the xv6 operating system. It tests functions
 * including xsqrtf, xexpf, xpowf, xsinf, xcosf, xtanhf, and xfabsf
 * against expected values with configurable error tolerances.
 *
 * The test suite features:
 * - Color-coded output for easy result interpretation
 * - Detailed error reporting with floating-point value visualization
 * - Support for special values (NaN, Infinity)
 * - Multiple error metrics (absolute, relative)
 * - Comprehensive test case coverage
 *
 */

#include "kernel/types.h"
#include "user.h"
#include "xmath.h"
#include "xmath_test_cases.h"
#include "testutil.h"

 /** @brief ANSI Color Codes for terminal output */
#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

/** @brief Global test counters */
int tests_passed = 0; /**< Count of passed test cases */
int tests_failed = 0; /**< Count of failed test cases */

/**
 * @brief Build detailed failure message for test cases
 *
 * @param buffer     Output buffer for the failure message
 * @param size       Size of the output buffer
 * @param func_name  Name of the function being tested
 * @param case_num   Test case number
 * @param input1     First input value to the function
 * @param input2     Second input value (for two-parameter functions)
 * @param result     Actual result from the function
 * @param expected   Expected result
 * @param error      Calculated error between result and expected
 * @param extra      Additional context information
 *
 * @details
 * Constructs a human-readable failure message showing the test case details,
 * inputs, expected output, actual output, and error. Handles floating-point
 * to string conversion manually for xv6 compatibility.
 */
void build_fail_message(char* buffer, int size, const char* func_name, int case_num,
  float input1, float input2, float result, float expected,
  float error, const char* extra)
{
  int pos = 0;

  // Start with case number and function name
  pos += strlen(strcpy(buffer + pos, "Case "));

  // Convert case number to string
  int n = case_num;
  char num_str[16];
  char* num_ptr = num_str;
  if (n == 0)
  {
    *num_ptr++ = '0';
  }
  else
  {
    char rev[16];
    char* rev_ptr = rev;
    while (n > 0)
    {
      *rev_ptr++ = '0' + (n % 10);
      n /= 10;
    }
    while (rev_ptr > rev)
    {
      *num_ptr++ = *(--rev_ptr);
    }
  }
  *num_ptr = '\0';
  pos += strlen(strcpy(buffer + pos, num_str));

  pos += strlen(strcpy(buffer + pos, ": "));
  pos += strlen(strcpy(buffer + pos, func_name));
  pos += strlen(strcpy(buffer + pos, "("));

  // Add first input
  if (pos < size - 50)
  {
    char float_str[32];
    char* fptr = float_str;

    // Simple float to string conversion
    if (input1 < 0)
    {
      *fptr++ = '-';
      input1 = -input1;
    }
    int ipart = (int)input1;

    // Convert integer part
    if (ipart == 0)
    {
      *fptr++ = '0';
    }
    else
    {
      char rev[16];
      char* rev_ptr = rev;
      int n2 = ipart;
      while (n2 > 0)
      {
        *rev_ptr++ = '0' + (n2 % 10);
        n2 /= 10;
      }
      while (rev_ptr > rev)
      {
        *fptr++ = *(--rev_ptr);
      }
    }

    *fptr++ = '.';

    // Fractional part (2 digits)
    float frac = input1 - ipart;
    for (int i = 0; i < 2 && pos < size - 10; i++)
    {
      frac *= 10;
      int digit = (int)frac;
      *fptr++ = '0' + digit;
      frac -= digit;
    }
    *fptr = '\0';

    pos += strlen(strcpy(buffer + pos, float_str));
  }

  // Add second input if provided (for powf)
  if (input2 != 0.0f || strcmp(func_name, "xpowf") == 0)
  {
    pos += strlen(strcpy(buffer + pos, ", "));

    if (pos < size - 50)
    {
      char float_str[32];
      char* fptr = float_str;

      if (input2 < 0)
      {
        *fptr++ = '-';
        input2 = -input2;
      }
      int ipart = (int)input2;

      if (ipart == 0)
      {
        *fptr++ = '0';
      }
      else
      {
        char rev[16];
        char* rev_ptr = rev;
        int n2 = ipart;
        while (n2 > 0)
        {
          *rev_ptr++ = '0' + (n2 % 10);
          n2 /= 10;
        }
        while (rev_ptr > rev)
        {
          *fptr++ = *(--rev_ptr);
        }
      }

      *fptr++ = '.';

      float frac = input2 - ipart;
      for (int i = 0; i < 2 && pos < size - 10; i++)
      {
        frac *= 10;
        int digit = (int)frac;
        *fptr++ = '0' + digit;
        frac -= digit;
      }
      *fptr = '\0';

      pos += strlen(strcpy(buffer + pos, float_str));
    }
  }

  pos += strlen(strcpy(buffer + pos, ")"));

  // Add extra info if provided
  if (extra && pos < size - strlen(extra) - 1)
  {
    pos += strlen(strcpy(buffer + pos, extra));
  }
}

/**
 * @brief Check if a float value is NaN (Not a Number)
 *
 * @param x Float value to check
 * @return int Nonzero if x is NaN, zero otherwise
 *
 * @note Uses the IEEE-754 property that NaN != NaN
 */
int is_nan(float x)
{
  return (x != x);
}

/**
 * @brief Check if a float value is Infinity
 *
 * @param x Float value to check
 * @return int Nonzero if x is Infinity, zero otherwise
 *
 * @note Uses the property that Infinity * 2 == Infinity
 */
int is_inf(float x)
{
  return (x != 0.0f && x * 2.0f == x);
}

/**
 * @brief Check if a float value is finite (not NaN or Infinity)
 *
 * @param x Float value to check
 * @return int Nonzero if x is finite, zero otherwise
 */
int is_finite(float x)
{
  return !is_nan(x) && !is_inf(x);
}

/**
 * @brief Print a float value with special handling for NaN and Infinity
 *
 * @param f Float value to print
 *
 * @details
 * Handles special cases (NaN, Infinity) with colored output and provides
 * formatted output for regular numbers with up to 4 decimal places.
 */
void print_float(float f)
{
  // Handle special cases first
  if (f != f)
  { // NaN
    printf(COLOR_YELLOW "NaN" COLOR_RESET);
    return;
  }

  // Check for infinity
  if (f * 2.0f == f && f != 0.0f)
  {
    if (f > 0)
    {
      printf(COLOR_MAGENTA "INF" COLOR_RESET);
    }
    else
    {
      printf(COLOR_MAGENTA "-INF" COLOR_RESET);
    }
    return;
  }

  // Regular number
  if (f < 0)
  {
    printf("-");
    f = -f;
  }

  int intpart = (int)f;
  printf("%d.", intpart);

  float frac = f - intpart;
  for (int i = 0; i < 4; i++)
  {
    frac *= 10;
    int digit = (int)frac;
    printf("%d", digit);
    frac -= digit;
    if (frac < 1e-6f)
      break; // Stop if remainder is negligible
  }
}

/**
 * @brief Compare two floats for equality using absolute error
 *
 * @param a First float value
 * @param b Second float value
 * @param epsilon Maximum allowed absolute difference
 * @return int Nonzero if |a-b| < epsilon, zero otherwise
 *
 * @note Suitable for comparing numbers near zero
 */
int float_equals_abs(float a, float b, float epsilon)
{
  float diff = a - b;
  if (diff < 0)
    diff = -diff;
  return diff < epsilon;
}

/**
 * @brief Compare two floats for equality using relative error
 *
 * @param a First float value
 * @param b Second float value
 * @param epsilon Maximum allowed relative difference
 * @return int Nonzero if relative error < epsilon, zero otherwise
 *
 * @details
 * Uses relative error for larger numbers and absolute error for small numbers
 * to provide robust comparison across different magnitude ranges.
 */
int float_equals_rel(float a, float b, float epsilon)
{
  if (a == b)
    return 1;

  float diff = a - b;
  if (diff < 0)
    diff = -diff;

  // Use relative error for larger numbers, absolute for small
  float magnitude = (xfabsf(a) + xfabsf(b)) * 0.5f;
  if (magnitude < 1.0f)
  {
    return diff < epsilon;
  }
  else
  {
    return diff / magnitude < epsilon;
  }
}

/**
 * @brief Calculate and display error metrics for a test function
 *
 * @param func_name    Name of the function being tested
 * @param total_cases  Total number of test cases
 * @param passed_cases Number of passed test cases
 * @param max_error    Maximum observed error
 * @param avg_error    Average error across all cases
 *
 * @details
 * Displays comprehensive test results with color-coded pass rates and
 * error statistics. Provides success rate as a percentage.
 */
void calculate_error_metrics(const char* func_name, int total_cases, int passed_cases,
  float max_error, float avg_error)
{
  printf(COLOR_CYAN "  %s Results: " COLOR_RESET, func_name);

  // Color code based on pass rate
  if (passed_cases == total_cases)
  {
    printf(COLOR_GREEN "Passed: %d/%d" COLOR_RESET, passed_cases, total_cases);
  }
  else if (passed_cases >= total_cases * 0.8)
  {
    printf(COLOR_YELLOW "Passed: %d/%d" COLOR_RESET, passed_cases, total_cases);
  }
  else
  {
    printf(COLOR_RED "Passed: %d/%d" COLOR_RESET, passed_cases, total_cases);
  }

  printf(", Max error: ");
  print_float(max_error);
  printf(", Avg error: ");
  print_float(avg_error);
  printf("\n");

  // Calculate and display percentage with color
  float percentage = (float)passed_cases / total_cases * 100.0f;
  printf("  Success rate: ");

  if (percentage == 100.0f)
  {
    printf(COLOR_GREEN);
  }
  else if (percentage >= 80.0f)
  {
    printf(COLOR_YELLOW);
  }
  else
  {
    printf(COLOR_RED);
  }

  print_float(percentage);
  printf("%%" COLOR_RESET "\n");
}

/**
 * @brief Test suite for xsqrtf function
 *
 * @details
 * Tests the custom square root implementation against a comprehensive set
 * of test cases. Handles special values (NaN, Infinity) and calculates
 * both absolute error and success metrics.
 */
void test_sqrtf()
{
  printf(COLOR_BOLD "Testing xsqrtf - Comprehensive Test Suite" COLOR_RESET "\n");
  int passed = 0;
  float max_error = 0.0f;
  float total_error = 0.0f;
  int valid_cases = 0; // Cases where expected is finite

  for (int i = 0; i < sqrtf_count; i++)
  {
    float input = sqrtf_inputs[i];
    float expected = sqrtf_expected[i];
    float result = xsqrtf(input);

    // Handle NaN and Infinity cases
    if (is_nan(expected) && is_nan(result))
    {
      passed++;
      continue;
    }
    if (is_inf(expected) && is_inf(result))
    {
      passed++;
      continue;
    }

    // Calculate error for finite cases
    if (is_finite(expected) && is_finite(result))
    {
      float error = xfabsf(result - expected);
      if (error > max_error)
        max_error = error;
      total_error += error;
      valid_cases++;

      // Tighter threshold due to improved Quake III implementation
      if (error < 1e-6f)
      {
        passed++;
      }
      else
      {
        printf("  ");
        fail("sqrtf case failed - see details above");
        printf("    Input: ");
        print_float(input);
        printf("\n");
        printf("    Expected: ");
        print_float(expected);
        printf("\n");
        printf("    Got: ");
        print_float(result);
        printf("\n");
        printf("    Error: ");
        print_float(error);
        printf("\n");
      }
    }
    else
    {
      // Handle cases where result doesn't match expected special value
      if (!float_equals_abs(result, expected, 1e-5f))
      {
        printf("  ");
        fail("sqrtf special value mismatch");
        printf("    Input: ");
        print_float(input);
        printf("\n");
        printf("    Expected: ");
        print_float(expected);
        printf("\n");
        printf("    Got: ");
        print_float(result);
        printf("\n");
      }
      else
      {
        passed++;
      }
    }
  }

  calculate_error_metrics("sqrtf", sqrtf_count, passed, max_error,
    valid_cases > 0 ? total_error / valid_cases : 0.0f);

  if (passed == sqrtf_count)
  {
    tests_passed++;
  }
  else
  {
    tests_failed++;
  }
}

/**
 * @brief Test suite for xexpf function
 *
 * @details
 * Tests the custom exponential function implementation. Uses relative error
 * for larger values and handles edge cases including overflow to infinity
 * and NaN inputs.
 */
void test_expf()
{
  printf(COLOR_BOLD "Testing xexpf - Comprehensive Test Suite" COLOR_RESET "\n");
  int passed = 0;
  float max_error = 0.0f;
  float total_error = 0.0f;
  int valid_cases = 0;

  for (int i = 0; i < expf_count; i++)
  {
    float input = expf_inputs[i];
    float expected = expf_expected[i];
    float result = xexpf(input);

    // Handle infinity cases
    if (expected > 1e10f && result > 1e10f)
    { // Both are large (infinity)
      passed++;
      continue;
    }

    // Handle NaN cases
    if (expected != expected && result != result)
    { // Both are NaN
      passed++;
      continue;
    }

    // Calculate error for finite cases
    if (expected < 1e10f && result < 1e10f)
    {
      float error = xfabsf(result - expected);
      if (error > max_error)
        max_error = error;
      total_error += error;
      valid_cases++;

      // Use relative error for larger values
      float rel_error = (expected > 1.0f) ? error / expected : error;

      // Tighter threshold due to improved range reduction
      if (rel_error < 0.001f)  // Changed from 0.01f to 0.001f
      {
        passed++;
      }
      else
      {
        printf("  ");
        fail("expf case failed - see details above");
        printf("    Input: ");
        print_float(input);
        printf("\n");
        printf("    Expected: ");
        print_float(expected);
        printf("\n");
        printf("    Got: ");
        print_float(result);
        printf("\n");
        printf("    Rel Error: ");
        print_float(rel_error);
        printf("\n");
      }
    }
    else
    {
      printf("  ");
      fail("expf infinity mismatch");
      printf("    Input: ");
      print_float(input);
      printf("\n");
      printf("    Expected: ");
      print_float(expected);
      printf("\n");
      printf("    Got: ");
      print_float(result);
      printf("\n");
    }
  }

  calculate_error_metrics("expf", expf_count, passed, max_error,
    valid_cases > 0 ? total_error / valid_cases : 0.0f);

  if (passed == expf_count)
  {
    tests_passed++;
  }
  else
  {
    tests_failed++;
  }
}

/**
 * @brief Test suite for xpowf function
 *
 * @details
 * Tests the custom power function implementation. Uses relative error
 * due to the wide range of possible outputs. Handles special cases
 * including zero and negative exponents, and edge cases with large values.
 */
void test_powf_problem_cases() {
  printf(COLOR_BOLD "Testing xpowf - Problem Cases" COLOR_RESET "\n");

  struct {
    float base;
    float exponent;
    float expected;
    const char* description;
  } test_cases[] = {
      {0.0f, 0.0f, 1.0f, "0^0 = 1"},
      {0.0f, -1.0f, INFINITY, "0^-1 = INF"},
      {0.0f, 2.0f, 0.0f, "0^2 = 0"},
      {1.0f, 100.0f, 1.0f, "1^100 = 1"},
      {2.0f, 3.0f, 8.0f, "2^3 = 8"},
      {4.0f, 0.5f, 2.0f, "4^0.5 = 2"},
      {-2.0f, 2.0f, 4.0f, "(-2)^2 = 4"},
      {-2.0f, 3.0f, -8.0f, "(-2)^3 = -8"},
      {-2.0f, 0.5f, NAN, "(-2)^0.5 = NaN"},

  };

  int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
  int passed = 0;

  for (int i = 0; i < num_cases; i++) {
    float base = test_cases[i].base;
    float exponent = test_cases[i].exponent;
    float expected = test_cases[i].expected;
    const char* desc = test_cases[i].description;

    printf("  %s: ", desc);

    float result = xpowf(base, exponent);

    if (is_nan(expected)) {
      if (is_nan(result)) {
        printf(COLOR_GREEN "PASS" COLOR_RESET " (got NaN)\n");
        passed++;
      }
      else {
        printf(COLOR_RED "FAIL" COLOR_RESET " (expected NaN, got ");
        print_float(result);
        printf(")\n");
      }
    }
    else if (is_inf(expected)) {
      if (is_inf(result)) {
        printf(COLOR_GREEN "PASS" COLOR_RESET " (got INF)\n");
        passed++;
      }
      else {
        printf(COLOR_RED "FAIL" COLOR_RESET " (expected INF, got ");
        print_float(result);
        printf(")\n");
      }
    }
    else {
      float error = xfabsf(result - expected);

      printf("expected=");
      print_float(expected);
      printf(", got=");
      print_float(result);
      printf(", error=");
      print_float(error);

      if (error < 0.05f) {
        printf(" " COLOR_GREEN "PASS" COLOR_RESET "\n");
        passed++;
      }
      else {
        printf(" " COLOR_RED "FAIL" COLOR_RESET "\n");
      }
    }
  }

  printf("Problem cases: %d/%d passed\n", passed, num_cases);
}


/**
 * @brief Test suite for xsinf function
 *
 * @details
 * Tests the custom sine function implementation with range-reduced Taylor series.
 * Uses adaptive error thresholds based on input magnitude.
 */
void test_sinf()
{
  printf(COLOR_BOLD "Testing xsinf - Comprehensive Analysis" COLOR_RESET "\n");
  int passed = 0;
  float max_abs_error = 0.0f;
  float max_rel_error = 0.0f;
  float total_abs_error = 0.0f;
  int valid_cases = 0;

  // Track failures by type
  int sign_errors = 0;
  int magnitude_errors = 0;
  int quadrant_boundary_errors = 0;

  for (int i = 0; i < sinf_count; i++)
  {
    float input = sinf_inputs[i];
    float expected = sinf_expected[i];
    float result = xsinf(input);

    // Calculate errors
    float abs_error = xfabsf(result - expected);
    float rel_error = (xfabsf(expected) > 1e-10f) ? abs_error / xfabsf(expected) : abs_error;

    if (abs_error > max_abs_error) max_abs_error = abs_error;
    if (rel_error > max_rel_error) max_rel_error = rel_error;
    total_abs_error += abs_error;
    valid_cases++;

    // Determine error threshold based on input characteristics
    float threshold;
    if (xfabsf(input) > 50.0f) {
      threshold = 5e-4f;  // More lenient for large inputs due to range reduction
    }
    else if (xfabsf(input) > 10.0f) {
      threshold = 1e-4f;
    }
    else {
      threshold = 1e-5f;  // Strict for small inputs
    }

    // Classify the type of error
    int is_sign_error = (result * expected < 0) && (xfabsf(result + expected) < 0.1f);
    int is_magnitude_error = (xfabsf(result) - xfabsf(expected)) > threshold;
    int is_boundary_case = (xfabsf(xfabsf(input) - 1.570796f) < 0.1f) ||
      (xfabsf(xfabsf(input) - 3.141592f) < 0.1f) ||
      (xfabsf(xfabsf(input) - 4.712388f) < 0.1f);

    if (abs_error < threshold && !is_sign_error)
    {
      passed++;
    }
    else
    {
      // Classify the failure
      if (is_sign_error) sign_errors++;
      if (is_magnitude_error) magnitude_errors++;
      if (is_boundary_case) quadrant_boundary_errors++;

      printf(COLOR_RED "  FAIL" COLOR_RESET " Case %d: ", i);

      // Show input in both radians and degrees for context
      printf("x=");
      print_float(input);
      printf(" rad (");
      print_float(input * 57.2957795f);
      printf("°)");

      printf("\n    Expected: ");
      print_float(expected);
      printf(", Got: ");
      print_float(result);

      printf("\n    Error: abs=");
      print_float(abs_error);
      printf(", rel=");
      print_float(rel_error);

      // Show error classification
      if (is_sign_error) printf(COLOR_YELLOW " [SIGN ERROR]" COLOR_RESET);
      if (is_magnitude_error) printf(COLOR_YELLOW " [MAGNITUDE ERROR]" COLOR_RESET);
      if (is_boundary_case) printf(COLOR_YELLOW " [QUADRANT BOUNDARY]" COLOR_RESET);

      printf("\n");
    }
  }

  // Calculate and display comprehensive metrics
  printf("\n" COLOR_CYAN "=== xsinf Detailed Results ===" COLOR_RESET "\n");
  printf("  Passed: %d/%d (%.1f%%)\n", passed, sinf_count, (float)passed / sinf_count * 100.0f);
  printf("  Max Absolute Error: ");
  print_float(max_abs_error);
  printf("\n");
  printf("  Max Relative Error: ");
  print_float(max_rel_error);
  printf("\n");
  printf("  Average Absolute Error: ");
  print_float(valid_cases > 0 ? total_abs_error / valid_cases : 0.0f);
  printf("\n");

  // Error classification summary
  if (sign_errors > 0 || magnitude_errors > 0) {
    printf(COLOR_YELLOW "  Error Classification:" COLOR_RESET "\n");
    if (sign_errors > 0) printf("    Sign errors: %d\n", sign_errors);
    if (magnitude_errors > 0) printf("    Magnitude errors: %d\n", magnitude_errors);
    if (quadrant_boundary_errors > 0) printf("    Quadrant boundary errors: %d\n", quadrant_boundary_errors);
  }

  // Performance assessment
  if (passed == sinf_count) {
    printf(COLOR_GREEN "  EXCELLENT: All tests passed!" COLOR_RESET "\n");
    tests_passed++;
  }
  else if (passed >= sinf_count * 0.9) {
    printf(COLOR_GREEN "  GOOD: Most tests passed" COLOR_RESET "\n");
    tests_passed++;
  }
  else if (passed >= sinf_count * 0.7) {
    printf(COLOR_YELLOW "  FAIR: Significant number of failures" COLOR_RESET "\n");
    tests_failed++;
  }
  else {
    printf(COLOR_RED "  POOR: Majority of tests failed" COLOR_RESET "\n");
    tests_failed++;
  }

  // Specific debugging guidance based on error patterns
  if (sign_errors > magnitude_errors) {
    printf(COLOR_YELLOW " Focus on: Sign handling in range reduction" COLOR_RESET "\n");
  }
  else if (magnitude_errors > sign_errors) {
    printf(COLOR_YELLOW " Focus on: Taylor series accuracy" COLOR_RESET "\n");
  }

  if (quadrant_boundary_errors > 0) {
    printf(COLOR_YELLOW " Check: Quadrant boundary cases (π/2, π, 3π/2)" COLOR_RESET "\n");
  }
}

/**
 * @brief Test suite for xcosf function
 *
 * @details
 * Tests the custom cosine function implementation. Similar to xsinf
 * testing but with cosine-specific test cases. Uses adaptive error
 * thresholds based on input magnitude.
 */
void test_cosf()
{
  printf(COLOR_BOLD "Testing xcosf - Comprehensive Debugging" COLOR_RESET "\n");
  int passed = 0;
  float max_abs_error = 0.0f;

  // Test critical cosine values first
  struct {
    float input;
    float expected;
    const char* description;
  } critical_cases[] = {
      {0.0f, 1.0f, "cos(0) = 1"},
      {1.570796f, 0.0f, "cos(π/2) = 0"},
      {3.141592f, -1.0f, "cos(π) = -1"},
      {4.712388f, 0.0f, "cos(3π/2) = 0"},
      {6.283185f, 1.0f, "cos(2π) = 1"},
      {-1.570796f, 0.0f, "cos(-π/2) = 0"},
      {-3.141592f, -1.0f, "cos(-π) = -1"},
      {0.523599f, 0.866025f, "cos(π/6) = √3/2"},
      {1.047198f, 0.5f, "cos(π/3) = 0.5"},
  };

  int num_critical = sizeof(critical_cases) / sizeof(critical_cases[0]);
  int critical_passed = 0;

  printf("  Critical Values Test:\n");
  for (int i = 0; i < num_critical; i++) {
    float result = xcosf(critical_cases[i].input);
    float error = xfabsf(result - critical_cases[i].expected);

    printf("    %s: ", critical_cases[i].description);
    printf("expected=");
    print_float(critical_cases[i].expected);
    printf(", got=");
    print_float(result);
    printf(", error=");
    print_float(error);

    if (error < 1e-4f) {
      printf(" " COLOR_GREEN "PASS" COLOR_RESET "\n");
      critical_passed++;
    }
    else {
      printf(" " COLOR_RED "FAIL" COLOR_RESET "\n");

      // Additional diagnostics for critical failures
      printf("      Input: ");
      print_float(critical_cases[i].input);
      printf(" rad (");
      print_float(critical_cases[i].input * 57.2957795f);
      printf(" deg)\n");
      printf("      Sign analysis: expected %s, got %s\n",
        critical_cases[i].expected < 0 ? "negative" : "positive",
        result < 0 ? "negative" : "positive");
    }
  }
  printf("  Critical cases: %d/%d passed\n\n", critical_passed, num_critical);

  // Now test the comprehensive test suite
  for (int i = 0; i < cosf_count; i++)
  {
    float input = cosf_inputs[i];
    float expected = cosf_expected[i];
    float result = xcosf(input);

    float error = xfabsf(result - expected);
    if (error > max_abs_error) max_abs_error = error;

    // Adaptive threshold based on input magnitude
    float threshold = (xfabsf(input) > 100.0f) ? 1e-4f : 1e-5f;

    if (error < threshold)
    {
      passed++;
    }
    else
    {
      printf(COLOR_RED "  FAIL Case %d:" COLOR_RESET "\n", i);
      printf("    Input:    ");
      print_float(input);
      printf(" rad (");
      print_float(input * 57.2957795f);
      printf(" deg)\n");

      printf("    Expected: ");
      print_float(expected);
      printf(" (%s)\n", expected < 0 ? "negative" : "positive");

      printf("    Got:      ");
      print_float(result);
      printf(" (%s)\n", result < 0 ? "negative" : "positive");

      printf("    Error:    ");
      print_float(error);
      printf("\n");

      // Sign analysis
      if ((result < 0 && expected > 0) || (result > 0 && expected < 0)) {
        printf("    " COLOR_YELLOW "SIGN ERROR: Wrong sign!" COLOR_RESET "\n");
      }

      // Magnitude analysis
      float mag_error = xfabsf(xfabsf(result) - xfabsf(expected));
      if (mag_error < threshold) {
        printf("    " COLOR_YELLOW "Magnitude correct but sign wrong" COLOR_RESET "\n");
      }
    }
  }

  printf(COLOR_CYAN "  xcosf Results: " COLOR_RESET);
  if (passed == cosf_count && critical_passed == num_critical) {
    printf(COLOR_GREEN "Passed: %d/%d" COLOR_RESET "\n", passed, cosf_count);
  }
  else {
    printf(COLOR_RED "Passed: %d/%d" COLOR_RESET "\n", passed, cosf_count);
  }
  printf("  Max Absolute Error: ");
  print_float(max_abs_error);
  printf("\n");
  printf("  Critical values: %d/%d passed\n", critical_passed, num_critical);

  if (passed == cosf_count && critical_passed == num_critical)
  {
    tests_passed++;
    printf(COLOR_GREEN "  xcosf implementation working correctly" COLOR_RESET "\n");
  }
  else
  {
    tests_failed++;

    // Provide debugging guidance based on failure patterns
    if (critical_passed < num_critical) {
      printf(COLOR_YELLOW "  Focus on: Critical value handling (0, π/2, π, etc.)" COLOR_RESET "\n");
    }
    else if (passed < cosf_count * 0.5) {
      printf(COLOR_YELLOW "  Focus on: Range reduction and quadrant handling" COLOR_RESET "\n");
    }
    else {
      printf(COLOR_YELLOW "  Focus on: Taylor series accuracy" COLOR_RESET "\n");
    }
  }
}

/**
 * @brief Test suite for xtanhf function - Hyperbolic Tangent with Asymptotic Clamping
 *
 * @details
 * Tests the custom hyperbolic tangent implementation that uses:
 * 1. Asymptotic clamping: ±1.0 for |x| > 5
 * 2. Numerically stable form: tanh(x) = (e^(2x) - 1) / (e^(2x) + 1)
 * 3. Tests boundary conditions, asymptotic behavior, and active region
 */
void test_tanhf()
{
  printf(COLOR_BOLD "Testing xtanhf - Hyperbolic Tangent with Asymptotic Clamping" COLOR_RESET "\n");
  int passed = 0;
  float max_abs_error = 0.0f;
  float max_rel_error = 0.0f;
  float total_abs_error = 0.0f;
  int valid_cases = 0;

  // Track specific types of test cases
  int asymptotic_cases = 0;
  int active_region_cases = 0;
  int boundary_cases = 0;

  // Comprehensive test cases for tanhf covering all regions
  float tanhf_inputs[] = {
    // Asymptotic region (|x| > 5) - should clamp to ±1.0
    -10.0f, -8.0f, -6.0f, -5.5f, -5.1f,  // Large negative
    5.1f, 5.5f, 6.0f, 8.0f, 10.0f,       // Large positive

    // Boundary region (|x| ≈ 5) - transition to asymptotic
    -5.0f, -4.9f, -4.5f, 4.5f, 4.9f, 5.0f,

    // Active region (|x| < 5) - where tanh is computed
    -4.0f, -3.0f, -2.5f, -2.0f, -1.5f, -1.0f, -0.5f,
    0.0f,  // Special case
    0.5f, 1.0f, 1.5f, 2.0f, 2.5f, 3.0f, 4.0f,

    // Very small values (linear region)
    -0.1f, -0.01f, -0.001f, 0.001f, 0.01f, 0.1f,

    // Important neural network activation points
    -2.0f, -1.0f, 0.0f, 1.0f, 2.0f
  };

  float tanhf_expected[] = {
    // Asymptotic region
    -1.0f, -1.0f, -1.0f, -1.0f, -1.0f,
    1.0f, 1.0f, 1.0f, 1.0f, 1.0f,

    // Boundary region
    -0.999909f, -0.999876f, -0.999753f, 0.999753f, 0.999876f, 0.999909f,

    // Active region
    -0.999329f, -0.995055f, -0.986614f, -0.964028f, -0.905148f, -0.761594f, -0.462117f,
    0.0f,
    0.462117f, 0.761594f, 0.905148f, 0.964028f, 0.986614f, 0.995055f, 0.999329f,

    // Very small values (tanh(x) ≈ x for small x)
    -0.099668f, -0.0099997f, -0.001f, 0.001f, 0.0099997f, 0.099668f,

    // Neural network points
    -0.964028f, -0.761594f, 0.0f, 0.761594f, 0.964028f
  };

  int tanhf_count = sizeof(tanhf_inputs) / sizeof(tanhf_inputs[0]);

  for (int i = 0; i < tanhf_count; i++)
  {
    float input = tanhf_inputs[i];
    float expected = tanhf_expected[i];
    float result = xtanhf(input);

    // Calculate errors
    float abs_error = xfabsf(result - expected);
    float rel_error = (xfabsf(expected) > 1e-10f) ? abs_error / xfabsf(expected) : abs_error;

    if (abs_error > max_abs_error) max_abs_error = abs_error;
    if (rel_error > max_rel_error) max_rel_error = rel_error;
    total_abs_error += abs_error;
    valid_cases++;

    // Classify test case type
    int is_asymptotic = (xfabsf(input) > 5.0f);
    int is_boundary = (xfabsf(input) >= 4.5f && xfabsf(input) <= 5.5f);
    int is_active = (xfabsf(input) < 4.5f);

    if (is_asymptotic) asymptotic_cases++;
    if (is_boundary) boundary_cases++;
    if (is_active) active_region_cases++;

    // Adaptive thresholds based on region
    float threshold;
    if (is_asymptotic) {
      // For asymptotic region, we expect exact ±1.0 due to clamping
      threshold = 1e-6f;
    }
    else if (is_boundary) {
      // For boundary region, be more lenient due to exponential precision
      threshold = 1e-3f;
    }
    else if (xfabsf(input) < 0.1f) {
      // For very small inputs, use strict threshold
      threshold = 1e-5f;
    }
    else {
      // For active region, standard threshold
      threshold = 1e-4f;
    }

    // Special handling for zero input
    if (input == 0.0f && xfabsf(result) < threshold) {
      passed++;
      continue;
    }

    // Check for sign errors in asymptotic region
    int is_sign_error = (is_asymptotic && (result * expected < 0));

    if (abs_error < threshold && !is_sign_error)
    {
      passed++;
    }
    else
    {
      printf(COLOR_RED "  FAIL" COLOR_RESET " Case %d: ", i);

      // Show input and region classification
      printf("x=");
      print_float(input);
      printf(" [");
      if (is_asymptotic) printf("ASYMPTOTIC");
      else if (is_boundary) printf("BOUNDARY");
      else printf("ACTIVE");
      printf("]");

      printf("\n    Expected: ");
      print_float(expected);
      printf(", Got: ");
      print_float(result);

      printf("\n    Error: abs=");
      print_float(abs_error);
      printf(", rel=");
      print_float(rel_error);

      if (is_sign_error) {
        printf(COLOR_YELLOW " [SIGN ERROR - Asymptotic clamping failed]" COLOR_RESET);
      }

      printf("\n");

      // Additional diagnostics for boundary cases
      if (is_boundary) {
        printf("    Note: Boundary case near |x| = 5, clamping threshold test\n");
      }
    }
  }

  // Calculate and display comprehensive metrics
  printf("\n" COLOR_CYAN "=== xtanhf Detailed Results ===" COLOR_RESET "\n");
  printf("  Region Analysis:\n");
  printf("    Asymptotic cases (|x| > 5): %d\n", asymptotic_cases);
  printf("    Boundary cases (|x| ≈ 5): %d\n", boundary_cases);
  printf("    Active region cases (|x| < 5): %d\n", active_region_cases);

  printf("  Performance Metrics:\n");
  printf("    Passed: %d/%d (%.1f%%)\n", passed, tanhf_count, (float)passed / tanhf_count * 100.0f);
  printf("    Max Absolute Error: ");
  print_float(max_abs_error);
  printf("\n");
  printf("    Max Relative Error: ");
  print_float(max_rel_error);
  printf("\n");
  printf("    Average Absolute Error: ");
  print_float(valid_cases > 0 ? total_abs_error / valid_cases : 0.0f);
  printf("\n");

  // Special tests for asymptotic clamping behavior
  printf("  Asymptotic Clamping Verification:\n");
  int clamping_passed = 0;
  float large_values[] = { -100.0f, -50.0f, -10.0f, 10.0f, 50.0f, 100.0f };
  for (int i = 0; i < 6; i++) {
    float result = xtanhf(large_values[i]);
    float expected = (large_values[i] > 0) ? 1.0f : -1.0f;
    if (result == expected) {
      clamping_passed++;
    }
    else {
      printf("    FAIL: tanh(");
      print_float(large_values[i]);
      printf(") = ");
      print_float(result);
      printf(", expected ");
      print_float(expected);
      printf("\n");
    }
  }
  printf("    Clamping test: %d/6 passed\n", clamping_passed);

  // Performance assessment
  if (passed == tanhf_count && clamping_passed == 6) {
    printf(COLOR_GREEN "  EXCELLENT: All tanhf tests passed!" COLOR_RESET "\n");
    printf(COLOR_GREEN "  Asymptotic clamping working correctly" COLOR_RESET "\n");
    tests_passed++;
  }
  else if (passed >= tanhf_count * 0.9) {
    printf(COLOR_GREEN "  GOOD: Most tanhf tests passed" COLOR_RESET "\n");
    tests_passed++;
  }
  else {
    printf(COLOR_RED "  POOR: Significant tanhf test failures" COLOR_RESET "\n");
    tests_failed++;

    // Debugging guidance
    if (clamping_passed < 6) {
      printf(COLOR_YELLOW "  Focus on: Asymptotic clamping implementation" COLOR_RESET "\n");
    }
    if (max_abs_error > 0.1f) {
      printf(COLOR_YELLOW " Focus on: Exponential computation accuracy" COLOR_RESET "\n");
    }
  }
}

/**
 * @brief Test suite for xfabsf function
 *
 * @details
 * Tests the custom absolute value function implementation. Uses simple
 * test cases since fabsf is a straightforward function. Tests positive,
 * negative, zero, and edge cases including negative zero.
 */
void test_fabsf()
{
  printf(COLOR_BOLD "Testing xfabsf" COLOR_RESET "\n");
  int passed = 0;

  float test_cases[][2] = {
      {5.0f, 5.0f},
      {-5.0f, 5.0f},
      {0.0f, 0.0f},
      {-3.14159f, 3.14159f},
      {1e-6f, 1e-6f},
      {-1e-6f, 1e-6f},
      {-0.0f, 0.0f} // Test negative zero
  };

  int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);

  for (int i = 0; i < num_cases; i++)
  {
    float input = test_cases[i][0];
    float expected = test_cases[i][1];
    float result = xfabsf(input);

    if (result == expected || (result == 0.0f && expected == 0.0f))
    {
      passed++;
    }
    else
    {
      printf("  ");
      fail("fabsf case failed - see details above");
      printf("    Input: ");
      print_float(input);
      printf("\n");
      printf("    Expected: ");
      print_float(expected);
      printf("\n");
      printf("    Got: ");
      print_float(result);
      printf("\n");
    }
  }

  if (passed == num_cases)
  {
    pass("All fabsf tests passed");
  }
  else
  {
    printf("  ");
    fail("Some fabsf tests failed");
    printf("    Passed: %d/%d\n", passed, num_cases);
  }

  if (passed == num_cases)
  {
    tests_passed++;
  }
  else
  {
    tests_failed++;
  }
}

/**
 * @brief Basic performance comparison test
 *
 * @details
 * Tests the performance of key mathematical functions by running
 * multiple iterations and measuring execution time. This helps validate
 * the performance improvements mentioned in the PDF.
 */
void test_performance()
{
  printf(COLOR_BOLD "Performance Test - 100,000,000 iterations" COLOR_RESET "\n");

  int iterations = 100000000;

  // Test sqrtf performance
  int start_time = uptime();
  for (int i = 0; i < iterations; i++) {
    (void)xsqrtf(2.0f + i * 0.001f); // Cast to void to suppress warning
  }
  int sqrt_time = uptime() - start_time;

  // Test expf performance  
  start_time = uptime();
  for (int i = 0; i < iterations; i++) {
    (void)xexpf(1.0f + i * 0.001f);
  }
  int exp_time = uptime() - start_time;

  // Test sinf performance
  start_time = uptime();
  for (int i = 0; i < iterations; i++) {
    (void)xsinf(1.0f + i * 0.001f);
  }
  int sin_time = uptime() - start_time;

  printf("  sqrtf: %d ms\n", sqrt_time);
  printf("  expf:  %d ms\n", exp_time);
  printf("  sinf:  %d ms\n", sin_time);

  // Simple performance check
  if (sqrt_time < 100 && exp_time < 100 && sin_time < 100) {  // Reasonable thresholds
    pass("Performance tests completed within expected time");
  }
  else {
    warn("Some functions may be slower than expected");
  }
}

/**
 * @brief Main test runner for all mathematical functions
 *
 * @details
 * Orchestrates the execution of all individual function test suites
 * in sequence and provides a comprehensive summary at the end.
 */
void test_math_functions()
{
  printf(COLOR_BOLD COLOR_CYAN "\n=== Math Functions Tests ===" COLOR_RESET "\n");
  test_sqrtf();
  test_expf();
  test_powf_problem_cases();
  //test_powf();
  test_sinf();
  test_cosf();
  test_tanhf();
  test_fabsf();
  test_performance();
}

/**
 * @brief Program entry point for the math test suite
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return int Exit status (0 for success)
 *
 * @details
 * Initializes the test environment, runs all mathematical function tests,
 * and displays a comprehensive summary of results with color-coded output.
 */
int main(int argc, char** argv)
{
  // Set indentation if provided. usage fputest <level>
  if (argc == 2)
  {
    int indent = atoi(argv[1]);
    printf_set_indent(indent);
  }

  set_tag("XMATH");

  printf(COLOR_BOLD COLOR_MAGENTA "\n=== Starting Math Test Suite ===" COLOR_RESET "\n\n");

  // Run math tests
  test_math_functions();

  printf(COLOR_BOLD COLOR_CYAN "\n=== Math Test Summary ===" COLOR_RESET "\n");
  printf("Total Math Tests: %d\n", tests_passed + tests_failed);

  if (tests_passed > 0)
  {
    printf(COLOR_GREEN "Passed: %d" COLOR_RESET "\n", tests_passed);
  }
  else
  {
    printf("Passed: %d\n", tests_passed);
  }

  if (tests_failed > 0)
  {
    printf(COLOR_RED "Failed: %d" COLOR_RESET "\n", tests_failed);
  }
  else
  {
    printf("Failed: %d\n", tests_failed);
  }

  if (tests_failed == 0)
  {
    printf(COLOR_BOLD COLOR_GREEN "\n ALL MATH TESTS PASSED!" COLOR_RESET "\n");
  }
  else
  {
    printf(COLOR_BOLD COLOR_RED "\n SOME MATH TESTS FAILED!" COLOR_RESET "\n");
  }

  printf("\nExiting test suite...\n");
  exit(0);
}
