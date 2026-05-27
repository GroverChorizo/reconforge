#!/usr/bin/env bash
# Phase 0 — scope hygiene. Run before everything else.
#
#   TARGET=sub.example.com SCOPE_FILE=scopes/example.json ./00-scope-check.sh
#
# Exits non-zero (3) if the target is out of scope. Designed to be the
# first step in master-pipeline.sh and any chained execution.

PHASE="scope"
. "$(dirname "$0")/_lib.sh"

require_target
ensure_scope "$TARGET"
log INFO "scope check passed — proceeding"
