// Reference methodology workspaces. Unlike PHASE_PAGES (which map a route to
// kill-chain phases and render copy-paste CLI commands via Command Forge), these
// are narrative playbooks: a build-your-own-harness workflow rendered by
// MethodologyWorkspace as phases, bug-class pattern cards, principles, and
// interactive checklists. Keyed by sidebar route id; App.jsx routes any
// METHODOLOGIES[route] here. Content is distilled — no live payloads — with the
// source attributed. Add a new methodology = one entry here + one SIDEBAR line.
export const METHODOLOGIES = {
  "ai-api-fuzzing": {
    eyebrow: "Methodology · AI-Assisted",
    title: "AI-Assisted API Fuzzing",
    sub: "Drive an LLM as a tireless API access-control pentester — recon the surface, wrap a deterministic probe layer as agent tools, and tune the harness for signal over noise.",
    source: {
      author: "brutecat (Arvin Shivram) + Michael Dalton",
      work: "Hacking Google with A.I.",
      url: "https://brutecat.com/articles/hacking-google-with-ai/",
      date: "2026-06-11",
    },
    thesis:
      "Turn an LLM into a tireless API pentester: (1) recon a complete map of the target's API surface, (2) wrap a deterministic probe/proxy layer as agent tools so the model only crafts payloads, and (3) ruthlessly tune for signal over noise so confirmed access-control bugs surface with replayable evidence.",

    // One factual operator line; scope_guard still constrains live execution.
    note: "Reference workflow — scope_guard gates live execution to declared targets.",

    phases: [
      {
        num: "01",
        label: "Surface & credential collection",
        summary:
          "The technique is gated by API keys + a complete endpoint inventory. Recon is ~90% of the work.",
        points: [
          "Inventory hosts/endpoints from traffic logs (a browser network interceptor over the target's web apps), keyword-permutation brute force, and certificate transparency logs.",
          "Liveness check: hit GET / and read the Server response header — a recognizable backend banner means a live, responding service.",
          "Pull machine-readable API specs (Swagger/OpenAPI equivalents). Some are public; most need a valid key. Archive everything — specs get pulled or locked over time, so a historical archive is an asset.",
          "Hidden endpoints: specs are often filtered by a visibility label. The same spec fetched with a privileged label can be materially larger. Enumerate labels × keys × hosts.",
          "Keys live in mobile apps, web bundles, and desktop binaries. One key usually has many sibling APIs enabled on its project — breadth of keys = breadth of reachable APIs. Capture each key's restriction metadata for later.",
        ],
        note: {
          kind: "hook",
          text: "ReconForge hook: this maps onto the existing passive-enum + permutation + CT-log + httpx stack. The new artifact is a key/spec store — {key → owning project, enabled APIs, restriction type+values} and {host → reachable specs, required labels}.",
        },
      },
      {
        num: "02",
        label: "Model the request lifecycle",
        summary:
          "Responses are only useful if you know why they came back. Reverse the pipeline into ordered rejection stages so the same status code stops being noise.",
        points: [
          "Order the stages: method resolution → content-type → key valid/enabled → key restrictions satisfied → auth credential → first-party-auth origin whitelist → key-project vs bearer-project match → visibility label → method blocked for project → processed.",
          "A JSON \"Method not found\" (404) usually means a missing visibility label, not a missing method — a real missing method returns HTML.",
          "A 401 SESSION_COOKIE_INVALID with cookie UNKNOWN usually means a non-whitelisted origin, not a bad cookie.",
          "A generic INVALID_ARGUMENT with no detail just means a wrong parameter — keep iterating params.",
          "Build a classifier that probes a known method per (key, API) and records which stage rejected it. The output is an enablement matrix: which keys work on which APIs, plus the exact origin/referer and restriction headers each needs.",
        ],
        note: {
          kind: "tip",
          text: "Normalize cryptic backend errors into your own enum (e.g. MISSING_REQUIRED_VISIBILITY_LABEL) with plain-English guidance attached — cryptic strings confuse the model; normalized errors keep it productive.",
        },
      },
      {
        num: "03",
        label: "Build the probe layer (API explorer / proxy)",
        summary:
          "A tool that takes any spec and fires a correct, fully-authenticated request — handling all the plumbing the model shouldn't reason about.",
        points: [
          "Auth abstraction: reverse the proprietary signed auth header once (session cookie + timestamp + origin + optional identifiers); expose a single identity knob (\"send as attacker account X\"). The model never sees the crypto.",
          "Origin/Referer matching: many APIs enforce an undocumented origin whitelist and you generally can't mismatch Origin and Referer — auto-select a compatible pair per endpoint.",
          "Key-restriction headers per key type: Server = IP allowlist (can't bypass — deprioritize), Browser = correct Referer, iOS = bundle-identifier header, Android = package-name + signing-cert fingerprint.",
          "Multi-key probing: fire the same request with every known key in one shot; responses differ by key for label-gated endpoints. Group identical responses by hash so the model reviews 3 distinct outcomes, not 300 duplicates.",
        ],
        note: {
          kind: "warn",
          text: "Advanced: internal-only services are often reachable through frontend proxy surfaces (batchexecute, GraphQL console APIs) that transcode to internal RPC — extra attack surface, with prod/staging/auth/unauth behavior differences. Treat each proxy surface as its own sub-project.",
        },
      },
      {
        num: "04",
        label: "Expose the probe layer as agent tools (MCP)",
        summary:
          "Give the model the minimum set of tools to test like a human, and nothing more.",
        points: [
          "Keep probe inputs minimal — track host/version server-side, strip verbose method-id prefixes. The model supplies only body, endpoint, path, and an optional identity handle.",
          "Abstract identity to a single value — \"send with attacker account X's session\" is one parameter; the proxy does the rest.",
          "Operation IDs are everything: every probe returns one, and a report is invalid without them. This is what makes findings un-hallucinatable.",
        ],
        tools: [
          "probe(endpoint, body, identity?) -> operation_id, grouped_results",
          "report(finding, evidence_operation_ids[]) -> ack   # requires op-ids as proof",
          "get_schema(endpoint) -> request/response schema   # fetch schema for endpoints outside the group",
          "confirm_complete(summary) -> validated | rejected   # the ONLY way to finish",
        ],
      },
      {
        num: "05",
        label: "Drive the agent for signal, not noise",
        summary:
          "Naïve \"run one pentest and explore\" fails two ways: the model quits early and it drowns you in junk. Fix both.",
        points: [
          "Force thoroughness (Ralph Wiggum loop): the only exit is confirm_complete(), which the harness rejects unless every endpoint in the set has ≥1 probe.",
          "Group-based classification: have the model classify endpoints into logical groups, then run one focused pentest per group. Carry findings forward; provide in-group schemas inline and fetch the rest behind get_schema to protect the context budget.",
          "Type discipline: use exact schema types — the backend strictly type-checks, so type-confusion is a dead end.",
          "ID enumeration is a technique, not a finding: on an incremental ID try ±1, ±2 and seeds (1, 2, 3, 100, 1000) and cross-reference IDs across endpoints — but never report mere enumerability.",
          "Substitute unknown param values (\"1\", \"test\", \"me\", fake UUIDs) rather than skipping an endpoint; send multiple probes per endpoint across auth states/IDs.",
          "Encode a crisp report / don't-report list and a severity rubric. Report immediately on confirmation; one bug = one report.",
        ],
        note: {
          kind: "tip",
          text: "The system prompt took the author ~a month to tune. The two problems to design against: validation pain (you must verify a finding cheaply) and noise (the model loves reporting 500s, 401/403/404s, and 200s with no private data). Encode the negatives as hard as the positives.",
        },
      },
      {
        num: "06",
        label: "Triage, validate, escalate",
        summary:
          "The agent surfaces basic access-control leads at scale; the big bugs come from a human chaining them.",
        points: [
          "Make findings replayable: the model embeds operation_ids in the report; the review UI expands each into the actual request + response with a Play button to re-fire and confirm.",
          "Escalate manually: a data leak (a list of account IDs, an ID → email map) becomes a primitive for the next step.",
          "A staging endpoint that mirrors prod turns a \"staging-only\" finding into real-data impact; two small bugs chain into deanonymization or account takeover.",
          "Keep a running leads → chains board — big writeups often start as a single AI-reported lead.",
        ],
      },
      {
        num: "07",
        label: "Report & escalate",
        summary:
          "Write up each finding with reproduction steps and replayable evidence.",
        points: [
          "Articulate impact in business terms, not just \"200 where 403 expected\" — clarity and impact are what land the finding.",
          "One vulnerability per report; dedupe; note chained impact explicitly.",
          "Map severity to the engagement's rating scale and justify it.",
        ],
      },
    ],

    patterns: [
      {
        title: "Staging / sandbox mirrors production",
        text: "Test-/sandbox-/autopush- host variants frequently point at production data and/or skip access-control checks present in prod; some even swap the key-check vs restriction-check order.",
        action: "For every target API, enumerate and probe its staging/sandbox hostnames; re-test prod-blocked IDs there.",
      },
      {
        title: "Hidden endpoints behind visibility labels",
        text: "Endpoints absent from the default spec appear when a privileged label is supplied. A JSON \"Method not found\" signals a missing label, not a missing method.",
        action: "Enumerate labels; treat label-gated methods as high-interest.",
      },
      {
        title: "IDOR via sequential / guessable IDs",
        text: "Many resource IDs are incremental integers or otherwise guessable.",
        action: "Enumerate to find resources, but only report when you can actually read confidential data — enumerability alone is not a finding.",
      },
      {
        title: "Cross-tenant config writes = privesc",
        text: "Config/permission endpoints (UpdateProjectConfig, setIamPolicy, addUser, org/account membership) sometimes do no authorization check.",
        action: "Test whether any authenticated account can read/modify another tenant's config, add itself to another org, or set itself as owner. A cross-tenant write is often the highest-impact bug.",
      },
      {
        title: "Origin / Referer whitelist quirks",
        text: "A misleading auth error can really mean \"non-whitelisted origin.\" Internal/corp origins are sometimes unrestricted; an API that only accepts corp origins is likely an internal service never meant to be public.",
        action: "On SESSION_COOKIE_INVALID, sweep candidate origins before concluding the credential is bad.",
      },
      {
        title: "Error messages as an intel channel",
        text: "Backend errors leak project numbers, internal service-account names, storage bucket names (→ project IDs), and internal table/index names.",
        action: "Harvest and diff error strings; they map relationships and reveal new targets.",
      },
      {
        title: "Frontend proxy → internal RPC",
        text: "batchexecute / GraphQL console surfaces transcode to internal RPC and expose otherwise-unreachable methods. Signature validation, schema introspection, and auth enforcement can differ across prod/staging/auth/unauth.",
        action: "Scrape the schema via introspection where enabled; find the mode where validation is weakest.",
      },
    ],

    principles: [
      "Determinism at the edges, creativity in the middle — all plumbing (auth, origin, key restrictions, multi-key) is deterministic code; the model only does the fuzzy part: payload/param creativity and pattern-spotting.",
      "Evidence handles defeat hallucination — nothing is real until a replayable operation_id proves it. Reports without evidence are structurally impossible.",
      "Forced completion beats prompting for diligence — a validating exit gate (confirm_complete) outperforms asking the model to be thorough.",
      "Context budget is a first-class constraint — group-scoped runs + schema-on-demand keep the window lean; dumping all schemas up front kills the run.",
      "Minimal tool inputs reduce error surface — every value tracked server-side is one the model can't get wrong.",
      "Signal/noise is a tuning loop, not a one-shot — expect weeks of system-prompt iteration; encode the negatives explicitly.",
    ],

    checklist: [
      "Pick one target with a broad API surface.",
      "Stand up a spec store and a key/restriction store (extend ReconForge's enum output).",
      "Implement the auth + origin + key-restriction library so a single identity param produces a correct request.",
      "Build the rejection-stage classifier and generate an enablement matrix for your target set.",
      "Add multi-key probing with response-hash grouping.",
      "Wrap probe / report / get_schema / confirm_complete as MCP tools; track host/version server-side.",
      "Write a v1 system prompt with explicit report/don't-report + severity rubric; plan to iterate.",
      "Add the Ralph Wiggum completion gate.",
      "Build a review UI that expands operation_ids into the real request + a replay button.",
      "Run group-scoped pentests; carry findings forward; triage by replay; escalate chains by hand.",
      "Draft a writeup template: surface → lead + evidence → escalation → impact → fix.",
    ],
  },
};
