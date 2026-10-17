"""RuleSmith: an autonomous detection-engineering agent.

Threat intel in, tested Sigma detection rules out. Every LLM call goes through
Nebius Token Factory to NVIDIA Nemotron models; every rule is validated by
actually executing it against telemetry before it is handed back.
"""

__version__ = "0.1.0"
