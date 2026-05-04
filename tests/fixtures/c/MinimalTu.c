/* Fixture: one external and one static function. ASCII-only. */

static int internal_dup(int x) {
  volatile int bump = x;
  return bump + 1;
}

int public_add(int a, int b) {
  return internal_dup(a) + internal_dup(b);
}
