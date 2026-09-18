/**
 * @file xmath.c
 * @brief Optimized mathematical function implementations for xv6 operating system
 * 
 * @author Hamna Sajid
 * @date 30th November 2025
 * 
 * @details
 * This file implements optimized mathematical functions using methods recommended
 * in the xv4 research paper. Implementations use range reduction, polynomial
 * approximations with Horner's method, and hardware-efficient algorithms.
 */

#include "kernel/types.h"
#include "user.h"
#include "xmath.h"

/****************************************************************************************
 *  ********* Constants for Horner's Method (Taylor Series for e^r around 0) *********
 * **************************************************************************************
 *
 * The Taylor series for e^r is 1 + r + r^2/2! + r^3/3! + ... + r^10/10!
 * We evaluate it using Horner's method:
 * e^r ≈ 1 + r*(1 + r/2*(1 + r/3*(1 + ...)))
 *
 * Fully unrolled for 10 terms. r is the reduced value after x = n*ln2 + r
 * where n is an integer and r is small.
 *
 ***************************************************************************************/
// Precomputed factorial reciprocals
#define EXP_C1  (1.0f / 1.0f);       // 1/1!
#define EXP_C2  (1.0f / 2.0f);       // 1/2!
#define EXP_C3  (1.0f / 6.0f);       // 1/3!
#define EXP_C4  (1.0f / 24.0f);      // 1/4!
#define EXP_C5  (1.0f / 120.0f);     // 1/5!
#define EXP_C6  (1.0f / 720.0f);     // 1/6!
#define EXP_C7  (1.0f / 5040.0f);    // 1/7!
#define EXP_C8  (1.0f / 40320.0f);   // 1/8!
#define EXP_C9  (1.0f / 362880.0f);  // 1/9!
#define EXP_C10 (1.0f / 3628800.0f); // 1/10!

/****************************************************************************************
 *  ********* Constants for Horner's Method (Taylor Series for Sine around 0) *********
 * **************************************************************************************
 *
 * The Taylor series for sin(x) is x - x^3/3! + x^5/5! - x^7/7! + ...
 * We can factor out x: x * (1 - x^2/3! + x^4/5! - x^6/7! + ...)
 * Let y = x^2. The inner polynomial P(y) = 1 - y/3! + y^2/5! - y^3/7! + ...
 * For 10 terms of the sine series, we need coefficients up to x^19/19!, which means y^9.
 * P(y) = c0 + c1*y + c2*y^2 + ... + c9*y^9
 * where c_k = (-1)^k / (2k + 1)!
 *
 * Coefficients for P(y) = 1 + c1*y + c2*y^2 + ... + c9*y^9
 * Note: c0 = 1, which will be handled as the first term in Horner's evaluation.
 * The constants below are c1 to c9.
 *
 * *************************************************************************************/

#define SINE_C1 (-1.0f/6.0f)               // -1/3!
#define SINE_C2 (8.33333333e-3f)           // 1/5!
#define SINE_C3 (-1.98412698e-4f)          // -1/7!
#define SINE_C4 (2.75573192e-6f)           // 1/9!
#define SINE_C5 (-2.50521084e-8f)          // -1/11!
#define SINE_C6 (1.60590438e-10f)          // 1/13!
#define SINE_C7 (-7.64716373e-13f)         // -1/15!
#define SINE_C8 (2.08767570e-15f)          // 1/17!
#define SINE_C9 (-8.22063525e-18f)         // -1/19!

/****************************************************************************************
 *  ********* Constants for Horner's Method (Taylor Series for Cosine around 0) ********
 * **************************************************************************************
 *
 * The Taylor series for cos(x) is 1 - x^2/2! + x^4/4! - x^6/6! + ...
 * Factor as polynomial in y = x^2: P(y) = 1 - y/2! + y^2/4! - y^3/6! + ...
 * For 10 terms (up to x^18/18!), we need coefficients up to y^9.
 * P(y) = c0 + c1*y + c2*y^2 + ... + c9*y^9
 * where c_k = (-1)^k / (2k)!
 *
 * Coefficients for P(y) = 1 + c1*y + c2*y^2 + ... + c9*y^9
 * Note: c0 = 1, handled in Horner's evaluation.
 *
 * *************************************************************************************/

#define COS_C1 (-0.5f)                       // -1/2!
#define COS_C2 (4.16666667e-2f)              // 1/4!
#define COS_C3 (-1.38888889e-3f)             // -1/6!
#define COS_C4 (2.48015873e-5f)              // 1/8!
#define COS_C5 (-2.75573192e-7f)             // -1/10!
#define COS_C6 (2.08767570e-9f)              // 1/12!
#define COS_C7 (-1.14707456e-11f)            // -1/14!
#define COS_C8 (4.77947733e-14f)             // 1/16!
#define COS_C9 (-1.56192070e-16f)            // -1/18!

/****************************************************************************************
 *  ********* Constants for Horner's Method (Taylor Series for ln(1+y) around 0) ******
 * **************************************************************************************
 *
 * The Taylor series for ln(1+y) is y - y^2/2 + y^3/3 - y^4/4 + ...
 * Factor as polynomial in y = m-1: P(y) = 1 - y/2 + y^2/3 - y^3/4 + ...
 * For 10 terms, we need coefficients up to y^9:
 * P(y) = c0 + c1*y + c2*y^2 + ... + c9*y^9
 * where c_k = (-1)^k / (k+1) for k=1..9
 *
 * Coefficients for P(y) = 1 + c1*y + c2*y^2 + ... + c9*y^9
 * Note: c0 = 1, handled in Horner's evaluation.
 *
 * *************************************************************************************/

#define LN_C1   (-0.5f)          // -1/2
#define LN_C2    0.33333333f     // 1/3
#define LN_C3   (-0.25f)         // -1/4
#define LN_C4    0.2f            // 1/5
#define LN_C5   (-0.16666667f)   // -1/6
#define LN_C6    0.14285714f     // 1/7
#define LN_C7   (-0.125f)        // -1/8
#define LN_C8    0.11111111f     // 1/9
#define LN_C9   (-0.1f)          // -1/10

float xsqrtf(float x) {
  // Use hardware instruction for the actual computation
  float result;
  asm volatile ("fsqrt.s %0, %1" : "=f"(result) : "f"(x));
  return result;
}

float xfabsf(float x) {
    // Use riscv instruction for absolute value
    float result;
    asm volatile ("fabs.s %0, %1" : "=f"(result) : "f"(x));
    return result;
}

float xpow2(int n) {
    // Clamp n to valid exponent range for float
    if (n < -126) n = -126;
    if (n > 127) n = 127;

    uint32 bits = (uint32)(n + 127) << 23; // shift n into exponent field
    float result;
    memcpy(&result, &bits, sizeof(result));
    return result;
}

float xfloorf(float val) {
    long long int_part = (long long)(val);
    // If val is positive or exactly an integer, static_cast truncates towards zero (which is floor).
    // If val is negative and not an exact integer (e.g., -2.5), static_cast truncates towards zero (-2),
    // so we need to subtract 1 to get the floor (-3).
    if (val < 0.0f && (float)(int_part) != val) {
        return (float)(int_part - 1);
    }
    return (float)(int_part);
}

float xmod(float x, float y) { // Renamed from fmod to mod
    // If y is zero, the modulo operation is undefined.
    // Returning 0.0f is a pragmatic choice for basic arithmetic,
    // but in a robust system, an error handling mechanism would be needed.
    if (y == 0.0f) return 0.0f;

    // Calculate n = floor(x / y) using the custom floor implementation.
    float n = xfloorf(x / y); // Use Utils::floor to call our custom implementation

    // Calculate the remainder: x - n * y
    return x - n * y;
}

float xexpf(float x) {
    // Handle special cases
    if (x == 0.0f) return 1.0f;
    if (x > 88.0f) return INFINITY;
    if (x < -88.0f) return 0.0f;

    // Range reduction: x = n*ln2 + r
    int n = (int)(x * INV_LN2);
    float r = x - n * LN2;

    float exp_r = EXP_C10;
    exp_r = exp_r * r + EXP_C9;
    exp_r = exp_r * r + EXP_C8;
    exp_r = exp_r * r + EXP_C7;
    exp_r = exp_r * r + EXP_C6;
    exp_r = exp_r * r + EXP_C5;
    exp_r = exp_r * r + EXP_C4;
    exp_r = exp_r * r + EXP_C3;
    exp_r = exp_r * r + EXP_C2;
    exp_r = exp_r * r + EXP_C1;
    exp_r = exp_r * r + 1.0f;

    // Compute 2^n inline using shifts
    return exp_r * xpow2(n);
}

float xlogf(float x) {
    if (x <= 0.0f) {
        if (x == 0.0f) return -INFINITY;
        return NAN;
    }
    if (x == 1.0f) return 0.0f;

    // Range reduction: x = m * 2^k, m in [0.5, 1)
    int exponent = 0;
    float m = x;
    while (m > 1.0f) { m *= 0.5f; exponent++; }
    while (m < 0.5f) { m *= 2.0f; exponent--; }

    float y = m - 1.0f;

    // Horner's method evaluation for P(y) = c0 + c1*y + c2*y^2 + ... + c9*y^9
    float result_poly = LN_C9;
    result_poly = result_poly * y + LN_C8;
    result_poly = result_poly * y + LN_C7;
    result_poly = result_poly * y + LN_C6;
    result_poly = result_poly * y + LN_C5;
    result_poly = result_poly * y + LN_C4;
    result_poly = result_poly * y + LN_C3;
    result_poly = result_poly * y + LN_C2;
    result_poly = result_poly * y + LN_C1;
    result_poly = result_poly * y + 1.0f; // Add implicit c0 = 1

    return exponent * LN2 + y * result_poly;
}

float xpowf(float x, float y) {
    // Handle special cases
    if (y == 0.0f) return 1.0f;
    if (x == 1.0f) return 1.0f;
    if (x == 0.0f) {
        if (y > 0.0f) return 0.0f;
        return 1.0f / 0.0f; // INFINITY
    }
    
    // pow(x,y) = exp(y * ln(|x|))
    float result = xexpf(y * xlogf(xfabsf(x)));
    
    // Handle negative base with integer exponent
    if (x < 0.0f) {
        // Check if exponent is integer
        int is_integer = (y == (float)(int)y);
        if (is_integer) {
            int int_y = (int)y;
            if (int_y % 2 != 0) { // Odd exponent
                result = -result;
            }
        } else {
            // Non-integer exponent with negative base -> NaN
            return NAN;
        }
    }
    
    return result;
}

float xsinf(float x) {
    // Define the period for sine function (2*PI)
    const float period = 2.0f * PI;

    // Apply the range reduction formula: PI - mod(x, 2*PI)
    // The modx function ensures mod(x, 2*PI) gives a result in [0, 2*PI).
    float reduced_x = PI - xmod(x, period);
    float x_squared = reduced_x * reduced_x; // y = x^2

    // Horner's method evaluation for P(y) = c0 + c1*y + c2*y^2 + ... + c9*y^9
    // P(y) = c0 + y * (c1 + y * (c2 + ... + y * (c9)...))
    // Our c0 is effectively 1 for the x(1 - y/3! + ...) form
    // Start with the innermost coefficient (c9) and work outwards.
    // Basically a bunch of FMADD (Multiply-Add) operations.
    float result_poly = SINE_C7; // 7 terms gives good accuracy/
    // result_poly = result_poly * x_squared + SINE_C8;
    // result_poly = result_poly * x_squared + SINE_C7;
    result_poly = result_poly * x_squared + SINE_C6;
    result_poly = result_poly * x_squared + SINE_C5;
    result_poly = result_poly * x_squared + SINE_C4;
    result_poly = result_poly * x_squared + SINE_C3;
    result_poly = result_poly * x_squared + SINE_C2;
    result_poly = result_poly * x_squared + SINE_C1;
    result_poly = result_poly * x_squared + 1.0f; // Add the implicit c0 = 1

    return reduced_x* result_poly;
}

float xcosf(float x) {
    // Define the period for cosine function (2*PI)
    const float period = 2.0f * PI;

    // Apply range reduction: PI - mod(x, 2*PI)
    float reduced_x = xmod(x + PI, period) - PI;
    float x_squared = reduced_x * reduced_x; // y = x^2

    // Horner's method evaluation for Q(y) = c0 + c1*y + c2*y^2 + ... + c9*y^9
    // Start with the innermost coefficient (c9) and work outwards
    float result_poly = COS_C9;
    result_poly = result_poly * x_squared + COS_C8;
    result_poly = result_poly * x_squared + COS_C7;
    result_poly = result_poly * x_squared + COS_C6;
    result_poly = result_poly * x_squared + COS_C5;
    result_poly = result_poly * x_squared + COS_C4;
    result_poly = result_poly * x_squared + COS_C3;
    result_poly = result_poly * x_squared + COS_C2;
    result_poly = result_poly * x_squared + COS_C1;
    result_poly = result_poly * x_squared + 1.0f; // Add the implicit c0 = 1

    return result_poly;
}

float xtanhf(float x) {

    // absolute value of x
    float abs_x = (x < 0.0f) ? -x : x;

    // sign as ±1.0f using ternary
    float sign = (x < 0.0f) ? -1.0f : 1.0f;

    if(abs_x > 5.0f) {
        // Asymptotic clamping
        return sign * 1.0f;
    }

    // 2. Calculate e^(2x)
    // NOTE: Replace std::exp with your custom/optimized exp function if available
    float exp_2x = xexpf(2.0f * x);

    // 3. Compute tanh(x) = (e^(2x) - 1) / (e^(2x) + 1)
    return (exp_2x - 1.0f) / (exp_2x + 1.0f);
}
