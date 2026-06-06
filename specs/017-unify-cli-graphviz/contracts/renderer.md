# Contract: graph renderer (CLI/graphviz)

## Preserved public surface

```python
# smartgraphical/core/graph.py
class GraphBuilder:
    def render(self, model, output_label) -> None: ...

# smartgraphical/services/analysis_service.py (unchanged)
class AnalysisService:
    def render_graph(self, context) -> None: ...  # calls GraphBuilder().render(model, path)
```

Signatures and call sites are unchanged. The CLI `task = 99` / run-all paths keep
calling `service.render_graph(context)`.

## Behavioural contract (new)

1. **Single source**: `render` MUST obtain its nodes/edges from
   `serializers.model_graph_to_dict(model)` — not from `model.types` /
   `model.call_edges` directly.
2. **Structural parity**: the node ids drawn MUST be exactly the canonical
   projection's node ids (clusters are the `type`/`tile` nodes; all other nodes
   are drawn with their canonical id). The web cytoscape view and the CLI PNG
   therefore reference identical node/edge identities.
3. **No silent drops**: every canonical node and edge MUST be represented; an
   unmapped `group`/`kind` falls back to a default style, never omission.
4. **Optional dependency**: if `graphviz` is not importable, `render` MUST print
   the existing not-installed message and return without raising.
5. **No side effects on the projection**: `render` MUST treat the canonical dict
   as read-only; the web payload (`model_graph_to_dict` / `model_summary_to_dict`)
   is byte-for-byte unchanged.
6. **Output artifact**: when graphviz is available, `render` emits the graph via
   `dot.render(output_label + ".gv", directory="", view=False)` as today.

## Verification

- `tests/unit/test_graph_renderer_unified.py`:
  - **Parity**: for Solidity/C/Rust fixtures, the set of node ids the renderer
    would draw equals `{n["id"] for n in model_graph_to_dict(model)["nodes"]}`.
    (Implemented by having `render` delegate to a pure helper that returns the
    (nodes, edges) it will draw, or by monkeypatching the `graphviz` module with a
    fake `Digraph` that records `node`/`edge`/`subgraph` calls — no real graphviz
    needed.)
  - **Graceful degradation**: with `core.graph.graphviz` set to `None`, `render`
    returns without raising and prints the message.
  - **No projection mutation**: `model_graph_to_dict(model)` output is equal
    before and after a `render` call.
- Existing suite (≥ 493) stays green; web graph contract/golden tests unchanged
  (SC-002).
