//! Software implementations of floating-point math functions.
//!
//! Provides approximations of `sqrt`, `sin`, `cos`, and `atan2` that work in
//! `no_std` environments without linking the `libm` crate. The accuracy is
//! sufficient for graphics geometry (Bezier evaluation, ellipse mid-point
//! tests, angle ranges).

/// Square root using the classic Newton-Raphson iteration.
pub fn sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut guess = x;
    for _ in 0..20 {
        guess = 0.5 * (guess + x / guess);
    }
    guess
}

/// Sine approximation using a small Taylor series.
pub fn sin(x: f64) -> f64 {
    let pi = core::f64::consts::PI;
    // Reduce x to the range [-pi, pi].
    let mut x = x % (2.0 * pi);
    if x > pi {
        x -= 2.0 * pi;
    } else if x < -pi {
        x += 2.0 * pi;
    }
    // Polynomial approximation, good enough for graphics purposes.
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    let x7 = x5 * x2;
    let x9 = x7 * x2;
    x - x3 / 6.0 + x5 / 120.0 - x7 / 5040.0 + x9 / 362880.0
}

/// Cosine: derived from the sine implementation.
pub fn cos(x: f64) -> f64 {
    sin(x + core::f64::consts::FRAC_PI_2)
}

/// Four-quadrant arctangent using a polynomial approximation.
/// Good for angle calculations in geometry code.
pub fn atan2(y: f64, x: f64) -> f64 {
    if x > 0.0 {
        atan(y / x)
    } else if x < 0.0 && y >= 0.0 {
        atan(y / x) + core::f64::consts::PI
    } else if x < 0.0 && y < 0.0 {
        atan(y / x) - core::f64::consts::PI
    } else if x == 0.0 && y > 0.0 {
        core::f64::consts::FRAC_PI_2
    } else if x == 0.0 && y < 0.0 {
        -core::f64::consts::FRAC_PI_2
    } else {
        0.0
    }
}

/// Internal single-argument arctangent approximation.
fn atan(x: f64) -> f64 {
    // Use the identity and a polynomial approximation on |x| < 1.
    let abs_x = x.abs();
    let reduced;
    let sign_correction;
    if abs_x > 1.0 {
        reduced = 1.0 / abs_x;
        sign_correction = core::f64::consts::FRAC_PI_2 - atancore(reduced);
    } else {
        reduced = abs_x;
        sign_correction = atancore(reduced);
    }
    if x < 0.0 {
        -sign_correction
    } else {
        sign_correction
    }
}

/// Core polynomial approximation for |x| < 1.
fn atancore(x: f64) -> f64 {
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    let x7 = x5 * x2;
    let x9 = x7 * x2;
    x - x3 / 3.0 + x5 / 5.0 - x7 / 7.0 + x9 / 9.0
}
