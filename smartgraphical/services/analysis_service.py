from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0, build_rule_registry
from smartgraphical.core.engine import RuleEngine
from smartgraphical.core.graph import GraphBuilder


class AnalysisService:
    def __init__(self, adapter=None, rule_engine=None, graph_builder=None):
        self.adapter = adapter or SolidityAdapterV0()
        self.rule_engine = rule_engine or RuleEngine(build_rule_registry())
        self.graph_builder = graph_builder or GraphBuilder()

    def analyze(self, source_path):
        return self.adapter.parse_source(source_path)

    def run_task(self, context, task_id):
        return self.rule_engine.run_task(context, task_id)

    def run_all(self, context):
        return self.rule_engine.run_all(context)

    def render_graph(self, context):
        self.graph_builder.render(context.normalized_model, context.path)
