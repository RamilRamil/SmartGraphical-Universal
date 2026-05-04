/* Fixture: struct + call edge for C graph heuristic tests. ASCII-only. */

struct Widget {
  int v;
};

static int getv(struct Widget const * w) {
  return w->v;
}

int widget_sum(struct Widget const * a, struct Widget const * b) {
  return getv(a) + getv(b);
}
