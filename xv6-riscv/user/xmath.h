/**
 * @file xmath.h
 * @author Hamna Sajid
 * 
 * @date 30th November 2025
 * 
 * @brief Optimized mathematical function declarations for xv6 operating system
 * 
 * @details
 * This header file declares optimized mathematical functions implemented
 * in xmath.c for the xv6 operating system. The functions utilize techniques
 * such as range reduction, Horner's method for polynomial evaluation, and
 * hardware-efficient algorithms to achieve high performance and accuracy.
 * 
 */

#ifndef XMATH_H
#define XMATH_H

/// @brief Positive infinity
#define INFINITY (1.0f / 0.0f)

/// @brief Not-a-Number (NaN)
#define NAN (0.0f / 0.0f)

/// @brief Pi (π)
#define PI 3.14159265358979323846f

/// @brief Pi divided by 2 (π/2)
#define PI_2 1.57079632679489661923f

/// @brief Pi divided by 4 (π/4)
#define PI_4 0.78539816339744830962f

/// @brief Small epsilon value
#define EPSILON 1e-5f

/// @brief Natural logarithm of 2 (ln(2))
#define LN2 0.69314718055994530942f

/// @brief Reciprocal of the natural logarithm of 2 (1/ln(2))
#define INV_LN2 1.44269504088896340736f


/**
 * @brief Hardware-accelerated square root using RISC-V fsqrt.s instruction
 * 
 * @param x Input value (must be non-negative)
 * @return float Square root of x, NaN if x is negative
 * 
 * @details
 * Uses the RISC-V F extension fsqrt.s instruction for maximum performance.
 * This is much faster and more accurate than any software implementation.
 */
float xsqrtf(float x);

/**
 * @brief Hardware-accelerated absolute value using RISC-V fabs.s instruction
 * 
 * @param x Input float value
 * @return float Absolute value of x
 * 
 * @details
 * Uses the RISC-V F extension fabs.s instruction for maximum performance.
 * This is more efficient than software implementations.
 */
float xfabsf(float x);

/**
 * @brief Computes 2 raised to the power of n as a float by directly manipulating
 *        the IEEE-754 single-precision exponent bits.
 *
 * This function takes an integer exponent `n` and returns the floating-point value
 * of 2^n. It works by constructing the float representation manually:
 * the exponent field of the IEEE-754 float is set to `n + 127` (bias),
 * and the mantissa is zero. This avoids runtime loops or multiplications.
 *
 * Values of `n` outside the valid float exponent range [-126, 127] are clamped
 * to prevent overflow or underflow.
 *
 * @param n The integer exponent.
 *          - Positive values correspond to 2^n.
 *          - Negative values correspond to fractional powers 2^n (e.g., n = -3 -> 1/8).
 * @return The float value of 2^n.
 *
 * @note This is a low-level bit manipulation implementation. It assumes a
 *       32-bit IEEE-754 single-precision float representation.
 * @note For very large positive or negative exponents, the value will be clamped
 *       to the closest representable float.
 */
float xpow2(int n);

/**
 * @brief Custom implementation of the floor function for floating-point numbers.
 * This function calculates the largest integer less than or equal to `val`.
 * It avoids using built-in functions like std::floor.
 *
 * @param val The floating-point value.
 * @return The floor of `val` as a float.
 */
float xfloorf(float x);

/**
 * @brief Custom implementation of the floating-point mathematical modulo function.
 * This function calculates the remainder of x divided by y, such that the result
 * has the same sign as the divisor (y).
 *
 * When y is positive, the result will always be non-negative and in the range [0, y).
 * For example, Utils::mod(-100.0f, 9.0f) will return 8.0f.
 * This behavior is crucial for consistent range reduction in periodic functions.
 *
 * This implementation avoids using built-in functions like std::fmod, std::floor, std::ceil, std::trunc.
 * It also does not handle NaN or Inf values gracefully as it avoids cmath.
 *
 * @param x The dividend.
 * @param y The divisor (period). For range reduction, y is typically positive.
 * @return The floating-point mathematical modulo (remainder with same sign as y).
 */
float xmod(float x, float y);

/**
 * @brief Computes e^x using range reduction: e^x = 2^n * e^r
 *
 * @param x Input value
 * @return Approximation of e^x
 */
float xexpf(float x);

/**
 * @brief Calculates the natural logarithm of a positive number using range reduction
 * to [0.5, 1.0) and a Horner-polynomial approximation for ln(1+y).
 *
 * This function first reduces the input `x` to the form x = m * 2^k with m in [0.5,1),
 * which improves the convergence of the polynomial approximation. After reduction,
 * Horner's method is used to evaluate the Taylor series for ln(1+y) efficiently.
 *
 * @param x The input value (x > 0)
 * @return The natural logarithm of x
 */
float xlogf(float x);

/**
 * @brief Compute power function x^y
 * 
 * @param x Base value
 * @param y Exponent value
 * @return float x raised to the power y
 * 
 * @details
 * Computes power function using identity: x^y = exp(y * ln(|x|))
 * Special case handling:
 * - x^0 = 1 for all x
 * - 1^y = 1 for all y
 * - 0^y = 0 for y > 0, INF for y <= 0
 * - Negative base with non-integer exponent returns NaN
 * - Negative base with odd integer exponent returns negative result
 * 
 * @note Uses absolute value of base for logarithm to handle negative bases properly
 */
float xpowf(float x, float y);

/**
 * @brief Calculates the sine of an angle using range reduction to (-PI, PI]
 * and then computes the sine using Horner's method for its Taylor series.
 *
 * This function first reduces the input angle `x` using the formula `PI - mod(x, 2*PI)`,
 * which maps `x` to the range `(-PI, PI]`. This centering around zero is highly beneficial
 * for maintaining the accuracy of Taylor series expansions, as they are most accurate
 * near their expansion point (0). After range reduction, Horner's method is applied
 * to the reduced angle.
 *
 * @param x The input angle in radians.
 * @return The sine of the angle, approximated using range reduction and Horner's method.
 */
float xsinf(float x);

/**
 * @brief Calculates the cosine of an angle using range reduction to (-PI, PI]
 * and then computes the cosine using Horner's method for its Taylor series.
 *
 * This function first reduces the input angle `x` using the formula `PI - mod(x, 2*PI)`,
 * which maps `x` to the range `(-PI, PI]`. Centering around zero improves the accuracy
 * of the Taylor series expansion, as it is most precise near 0. After range reduction,
 * Horner's method is applied to compute the polynomial approximation for cosine.
 *
 * @param x The input angle in radians.
 * @return The cosine of the angle, approximated using range reduction and Horner's method.
 */
float xcosf(float x);

/**
 * @brief Calculates the hyperbolic tangent (tanh) using asymptotic range clamping and definition.
 *
 * This function clamps the input `x` to the asymptotic bounds of tanh:
 * - For `x < -5`, returns -1.0f
 * - For `x > 5`, returns 1.0f
 * - For `-5 <= x <= 5`, applies a Taylor series approximation around 0.
 *
 * @param x The input value.
 * @return The hyperbolic tangent of the input, approximated using range clamping and Taylor series.
 */
float xtanhf(float x);  



#endif // XMATH_H