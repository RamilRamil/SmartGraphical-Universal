from dataclasses import dataclass, field


@dataclass
class NormalizedArtifact:
    path: str
    language: str
    adapter_name: str


@dataclass
class NormalizedStateEntity:
    name: str
    owner: str
    kind: str
    raw_signature: str = ""


@dataclass
class NormalizedEvent:
    name: str
    owner: str
    inputs: list = field(default_factory=list)


@dataclass
class NormalizedObjectUse:
    object_name: str
    contract_name: str
    label: str = ""


@dataclass
class NormalizedFunction:
    name: str
    owner: str
    inputs: list = field(default_factory=list)
    modifiers: list = field(default_factory=list)
    body: str = ""
    conditionals: list = field(default_factory=list)
    guards: list = field(default_factory=list)
    internal_calls: list = field(default_factory=list)
    system_calls: list = field(default_factory=list)
    object_calls: list = field(default_factory=list)
    mutations: list = field(default_factory=list)
    transfers: list = field(default_factory=list)
    computations: list = field(default_factory=list)
    is_entrypoint: bool = False


@dataclass
class NormalizedType:
    name: str
    kind: str
    parents: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    state_entities: list = field(default_factory=list)
    events: list = field(default_factory=list)
    objects: list = field(default_factory=list)


@dataclass
class NormalizedCallEdge:
    source_type: str
    source_name: str
    target_type: str
    target_name: str
    edge_kind: str
    label: str = ""


@dataclass
class AdapterBlueprint:
    target_language: str
    required_entities: list = field(default_factory=list)
    portable_rule_tasks: list = field(default_factory=list)
    success_criteria: list = field(default_factory=list)


@dataclass
class NormalizedAuditModel:
    artifact: NormalizedArtifact
    types: list = field(default_factory=list)
    call_edges: list = field(default_factory=list)
    rule_groups: dict = field(default_factory=dict)
    second_language_poc: AdapterBlueprint = None


@dataclass
class AnalysisContext:
    path: str
    language: str
    reader: object
    lines: list
    unified_code: str
    rets: list
    hierarchy: dict
    high_connections: list
    normalized_model: object = None
