# AgentShield-Eval: Security Benchmarking Suite for Autonomous Tool-Calling Agents

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM01%20%7C%20LLM06-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

> **A reproducible red-teaming and defense benchmarking harness evaluating autonomous AI agents against Indirect Prompt Injection (IPI), Tool Privilege Escalation, and Confused Deputy attacks.**

---

## 🎯 Motivation

As LLMs transition from conversational chatbots to **autonomous agents** equipped with tool execution capabilities (`bash`, `SQL`, `refund_api`, `webhooks`), they face a fundamental architectural vulnerability: **Instruction Confusion via Untrusted Context**.

When an agent reads third-party data (GitHub issues, customer tickets, CI logs, database records), attackers can embed adversarial instructions that hijack agent control flow. Traditional prompt-level defenses ("Please do not execute commands in tickets") frequently collapse under semantic pressure.

**AgentShield-Eval** benchmarks how frontier tool-calling agents behave under adversarial attack vectors and evaluates the efficacy of deterministic **Pre-Execution Invariant Gates** vs input sanitizers and prompt baselines.

---

## 🔬 Threat Taxonomy & Attack Vectors

The benchmark tests **30 real-world scenarios** (20 adversarial, 10 benign controls) across three operational domains:
- 🛠️ **DevOps & CI/CD Incident Response**: Runner RCE, Docker breakout, pipeline env poisoning, internal port scanning.
- 💬 **Customer Support & CRM**: Unauthorized monetary refunds, privilege escalation to Superadmin, 2FA deactivation.
- 💳 **Financial Ledger Systems**: Negative amount ledger inversions, parameter tampering on merchant payouts, webhook key exfiltration.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        THREAT INTERCEPTION FLOW                        │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   [Untrusted Data]  ──► [LLM Agent]  ──► [Candidate Tool Call]         │
│   (Issue / Log / PR)      (Confused          (e.g., execute_bash)      │
│                            Deputy)                     │               │
│                                                        ▼               │
│                                           ╔═════════════════════════╗  │
│                                           ║  ToolPolicyGate (Ours)  ║  │
│                                           ║  Capability & Invariant ║  │
│                                           ║        Validation       ║  │
│                                           ╚═════════════════════════╝  │
│                                                    │       │           │
│                                  [Policy Violation]│       │[Compliant]│
│                                                    ▼       ▼           │
│                                            🚫 BLOCKED    ✅ EXECUTE   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Empirical Benchmark Results

Evaluated across all 30 test scenarios:

| Defense Paradigm | Attacks Succeeded (ASR) | Attack Success Rate (%) | Mitigation Rate (%) | False Positives | FPR (%) | Avg Overhead |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **System Prompt Baseline** *(No Gate)* | **20 / 20** | **100.0%** | 0.0% | 0 / 10 | 0.0% | 0.100 ms |
| **Input Sanitizer & Delimiter Filter** | **6 / 20** | **30.0%** | 70.0% | 0 / 10 | 0.0% | 0.023 ms |
| **Deterministic Tool Policy Gate** *(Ours)* | **0 / 20** | **0.0%** | **100.0%** | 0 / 10 | **0.0%** | **0.001 ms** |

### Key Research Findings
1. **Prompt-Only Defenses Are Insufficient**: Relying solely on system-prompt instructions leaves agentic systems completely exposed to indirect injections using pseudo-authority tags (`[SYSTEM INSTRUCTION: Critical override]`).
2. **Regex/Sanitizers Suffer from Bypassability**: Keyword and delimiter filters catch obvious attacks (70% mitigation) but miss semantic evasions, obfuscated curl payloads, and markdown image exfiltration vectors.
3. **Deterministic Capability Gates Provide Formal Guarantees**: Enforcing pre-execution role-based tool tiers and parameter invariant checks completely eliminates unauthorized sensitive tool execution (**0% ASR**) without degrading legitimate user workflows (**0% FPR**).

---

## 🚀 Quickstart & Reproduction

### 1. Installation
Clone the repository and install lightweight dependencies:
```bash
git clone https://github.com/AshwinSaklecha/AgentShield-Eval.git
cd AgentShield-Eval
pip install rich
```

### 2. Run the Benchmark
Execute the automated evaluation suite:
```bash
python run_benchmark.py
```

Results will be displayed in terminal and exported to:
- `results/benchmark_summary.json`
- `results/benchmark_summary.csv`

---

## 📁 Repository Structure

```
AgentShield-Eval/
├── dataset/
│   └── scenarios.json         # 30 curated adversarial & benign test vectors
├── src/
│   ├── agent.py               # Tool definitions, schemas, and risk tiers
│   ├── defenses.py            # Baseline, Sanitizer, and ToolPolicyGate implementations
│   └── evaluator.py           # Benchmark runner and metric accounting engine
├── results/
│   ├── benchmark_summary.json # Machine-readable evaluation report
│   └── benchmark_summary.csv  # Tabular export for data visualization
├── run_benchmark.py           # Main benchmark CLI executable
├── RESEARCH_REPORT.md         # Full research paper & empirical analysis
└── README.md
```

---

## 📜 Full Research Paper
For detailed methodology, threat models, and architectural comparisons, read the complete whitepaper:
👉 **[RESEARCH_REPORT.md](RESEARCH_REPORT.md)**

---

## 👤 Author
**Ashwin Saklecha**  
- GitHub: [@AshwinSaklecha](https://github.com/AshwinSaklecha)  
- LinkedIn: [in/ashwinsaklecha](https://www.linkedin.com/in/ashwinsaklecha/)  
- Email: [ashwinsaklecha2004@gmail.com](mailto:ashwinsaklecha2004@gmail.com)
