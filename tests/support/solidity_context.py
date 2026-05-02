"""Synthetic AnalysisContext factories for Solidity rule unit tests."""

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedType,
)


def minimal_audit_model(contract_name="C"):
    """Return an empty normalized model with one contract-like type."""

    artifact = NormalizedArtifact(path="x.sol", language="solidity", adapter_name="Test")
    model = NormalizedAuditModel(artifact=artifact)
    model.types.append(NormalizedType(name=contract_name, kind="contract_like"))
    return model


def analysis_context_stub(
    normalized_model=None,
    *,
    path="x.sol",
    lines=None,
    rets=None,
    reader=None,
    unified_code="",
    hierarchy=None,
    high_connections=None,
):
    return AnalysisContext(
        path=path,
        language="solidity",
        reader=reader,
        lines=lines if lines is not None else [],
        unified_code=unified_code,
        rets=rets if rets is not None else [],
        hierarchy=hierarchy if hierarchy is not None else {},
        high_connections=high_connections if high_connections is not None else [],
        normalized_model=normalized_model,
    )


class TextLineSepReader:
    """Minimal reader shim for naming rules that need line_sep."""

    line_sep = "\n"


def make_legacy_contract_ret(
    contract_name="C",
    *,
    funcs=None,
    vars_list=None,
    structs=None,
):
    """Build one entry of `rets` shaped like ContractReader.__call__ output."""
    funcs = funcs or []
    vars_list = vars_list or []
    structs = structs or []
    imps = []
    var_func_mapping = {}
    func_func_mapping = {}
    sysfunc_func_mapping = {}
    obj_func_mapping = {}
    func_conditionals = [[] for _ in funcs]
    constructor = []
    evt_details = []
    objs = []
    using = ""
    return [
        contract_name,
        funcs,
        vars_list,
        structs,
        imps,
        var_func_mapping,
        func_func_mapping,
        sysfunc_func_mapping,
        obj_func_mapping,
        func_conditionals,
        constructor,
        evt_details,
        objs,
        using,
    ]
