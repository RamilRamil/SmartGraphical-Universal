from smartgraphical.adapters.base import AnalysisAdapter
from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0, build_rule_registry
from smartgraphical.core.engine import RuleEngine
from smartgraphical.core.graph import GraphBuilder
from smartgraphical.core.dataflow.taint import apply_taint


class AnalysisService:
    def __init__(self, adapter: AnalysisAdapter | None = None, rule_engine=None, graph_builder=None):
        # Any object satisfying the AnalysisAdapter contract is accepted here;
        # this is the single seam where every language adapter is consumed.
        self.adapter: AnalysisAdapter = adapter or SolidityAdapterV0()
        self.rule_engine = rule_engine or RuleEngine(build_rule_registry())
        self.graph_builder = graph_builder or GraphBuilder()

    def analyze(self, source_path, **parse_kwargs):
        context = self.adapter.parse_source(source_path, **parse_kwargs)
        model = getattr(context, "normalized_model", None)
        if model is not None:
            apply_taint(model)
        return context

    def run_task(self, context, task_id):
        return self.rule_engine.run_task(context, task_id)

    def run_all(self, context):
        return self.rule_engine.run_all(context)

    def render_graph(self, context):
        self.graph_builder.render(context.normalized_model, context.path)
