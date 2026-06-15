"""Tool gate, runner, registry, detection. Extracted from main.py incrementally.

Phase 7 will move the per-tool runners (_run_amass, _run_subfinder, etc.) here
and expose them as @tool decorators for the Recon agent. Phase 11 adds
detect.py (system tool detection + apt/go install plans).

Currently main.py still owns the runners; this package is the future home.

Research-only extensions are imported for their registry side effects. They add
passive/local/taxonomy tools used by malware-adjacent and methodology workflows
without enabling C2, payload, listener, persistence, or callback execution.
"""

# Import for registry side effects. Keep this at package import time so callers
# using ``from tools import registry`` see the research tools in REGISTRY.
from . import research_tools as _research_tools  # noqa: F401
