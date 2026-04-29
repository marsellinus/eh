"""Report module: generation, risk scoring, comparison, visualization, recommendations."""
from .generator       import generate_report, generate_comparison_summary
from .risk_scorer     import score_all, RiskScore
from .comparator      import compare, ComparisonDelta
from .recommendations import generate as generate_recommendations
from .visualizer      import generate_all_charts
from .academic_report import build as build_academic_report

__all__ = [
    "generate_report", "generate_comparison_summary",
    "score_all", "RiskScore",
    "compare", "ComparisonDelta",
    "generate_recommendations",
    "generate_all_charts",
    "build_academic_report",
]
