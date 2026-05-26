# Implementation Plan: Graph Legend and Details Panel Clarity

**Spec**: [spec.md](./spec.md)

## Touch points

| File | Change |
|------|--------|
| `frontend/src/components/GraphView.tsx` | NODE_GUIDE_ROWS; import usage markup; border hint in meta |
| `frontend/src/styles.css` | `.sg-graph__detail-list*`, meta dd overflow, code block width |

## Border semantics (document)

| Visual | Meaning |
|--------|---------|
| Orange border (2px) | `is_entrypoint` — public or external function |
| Red border (3px) | `sg-state-write` — may write storage |
| Dark red double (5px) | entrypoint + state writer |
