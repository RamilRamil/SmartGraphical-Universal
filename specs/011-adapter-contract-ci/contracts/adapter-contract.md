# Contract: AnalysisAdapter

**Location**: `smartgraphical/adapters/base.py` (new)

**Type**: `typing.Protocol` (structural). Enforced at test time by
`tests/unit/test_adapter_contract_conformance.py`.

## Interface

```python
from typing import Protocol
from smartgraphical.core.model import AnalysisContext


class AnalysisAdapter(Protocol):
    def parse_source(
        self,
        source_path: str,
        *,
        expand_local_imports: bool = True,
    ) -> AnalysisContext:
        ...
```

## Rules

- **R1 (single signature)**: every registered adapter's `parse_source` MUST match
  this signature: positional `source_path` only, keyword-only
  `expand_local_imports` defaulting to `True`.
- **R2 (uniform flag)**: `expand_local_imports` MUST be accepted by all adapters.
  Adapters without local-import expansion (C, Rust today) MUST treat it as a
  no-op and MUST NOT raise.
- **R3 (return shape)**: MUST return an `AnalysisContext` with a non-null
  `normalized_model`, `path`, `language`, `lines`, and `unified_code`.
- **R4 (backward compatibility)**: the Solidity adapter is the reference; its
  behavior and output MUST NOT change. Existing Solidity tests are the guard.
- **R5 (no new heavy dependency)**: implementing this contract MUST NOT introduce
  an AST/grammar/parser dependency (constitution Principle I).

## Caller expectations (unchanged)

- `AnalysisService.analyze(source_path, **parse_kwargs)` forwards kwargs to
  `parse_source`; with this contract, `expand_local_imports` is always safe to
  forward regardless of language.
- `web_api._analyze_source` may pass `expand_local_imports=False` for bundle
  members and `True` for single files, for every language, without branching.

## Conformance test (FR-003) outline

```python
# tests/unit/test_adapter_contract_conformance.py
import inspect
ADAPTERS = [SolidityAdapterV0(), CBaseAdapterV0(), RustStellarAdapterV0()]

for adapter in ADAPTERS:
    sig = inspect.signature(adapter.parse_source)
    assert "expand_local_imports" in sig.parameters            # R1/R2
    # no required positional beyond source_path                  # R1
    ctx_true = adapter.parse_source(FIXTURE[lang], expand_local_imports=True)
    ctx_false = adapter.parse_source(FIXTURE[lang], expand_local_imports=False)
    assert ctx_true.normalized_model is not None                # R3
    assert ctx_false.normalized_model is not None               # R2/R3
```

A deliberate signature break on any adapter MUST fail this test and name the
class.
