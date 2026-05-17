"""Tool gate, runner, registry, detection. Extracted from main.py incrementally.

Phase 7 will move the per-tool runners (_run_amass, _run_subfinder, etc.) here
and expose them as @tool decorators for the Recon agent. Phase 11 adds
detect.py (system tool detection + apt/go install plans).

Currently main.py still owns the runners; this package is the future home.
"""
