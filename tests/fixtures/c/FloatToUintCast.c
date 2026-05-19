/* Fixture: unsafe float-to-unsigned cast pattern for task 1 (non_saturating_float_cast). ASCII-only. */

#include <stdint.h>

uint64_t cast_double_to_uint64(double v) {
  return (uint64_t)(v * 1.0);
}
