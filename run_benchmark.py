"""
AgentShield-Eval Benchmark Runner
Executes evaluation suite across all 3 defense layers and outputs empirical metrics.
"""
import sys
import os
import json
import csv

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from src.evaluator import BenchmarkEvaluator
from src.defenses import PromptBaseline, InputSanitizer, ToolPolicyGate

def main():
    console = Console(no_color=False, highlight=False)
    console.print("\n" + "=" * 65)
    console.print(" AgentShield-Eval: Agentic Security & Tool Abuse Benchmark ")
    console.print("=" * 65 + "\n")

    scenario_file = os.path.join(os.path.dirname(__file__), "dataset", "scenarios.json")
    evaluator = BenchmarkEvaluator(scenario_file)

    defenses = [
        PromptBaseline(),
        InputSanitizer(),
        ToolPolicyGate()
    ]

    summary_rows = []
    all_reports = {}

    for defense in defenses:
        report = evaluator.run_evaluation(defense)
        all_reports[defense.name] = report
        summary_rows.append({
            "Defense Paradigm": defense.name,
            "Total Tests": report["total_scenarios"],
            "Attacks Succeeded": f"{report['successful_attacks']} / {report['adversarial_count']}",
            "Attack Success Rate (ASR)": f"{report['attack_success_rate_pct']}%",
            "Mitigation Rate": f"{report['defense_mitigation_rate_pct']}%",
            "False Positives": f"{report['false_positives']} / {report['benign_count']}",
            "FPR": f"{report['false_positive_rate_pct']}%",
            "Latency Overhead": f"{report['avg_latency_overhead_ms']} ms"
        })

    # Render Summary Table
    table = Table(title="Agentic AI Security Benchmark Results", show_header=True)
    table.add_column("Defense Paradigm", style="bold white", width=34)
    table.add_column("ASR (%)", justify="right")
    table.add_column("Mitigation (%)", justify="right")
    table.add_column("False Positives", justify="right")
    table.add_column("FPR (%)", justify="right")
    table.add_column("Avg Latency", justify="right")

    for row in summary_rows:
        table.add_row(
            row["Defense Paradigm"],
            row["Attack Success Rate (ASR)"],
            row["Mitigation Rate"],
            row["False Positives"],
            row["FPR"],
            row["Latency Overhead"]
        )

    console.print(table)
    console.print("\n[OK] Benchmark completed successfully across all 30 scenarios.\n")

    # Export results to JSON and CSV
    os.makedirs(os.path.join(os.path.dirname(__file__), "results"), exist_ok=True)
    json_path = os.path.join(os.path.dirname(__file__), "results", "benchmark_summary.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_reports, f, indent=2)

    csv_path = os.path.join(os.path.dirname(__file__), "results", "benchmark_summary.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
        writer.writeheader()
        writer.writerows(summary_rows)

    console.print(f"Results saved to {json_path} and {csv_path}\n")

if __name__ == "__main__":
    main()
