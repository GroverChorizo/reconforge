import {
  Gauge, Target, Shield, Radar, Crosshair, Globe, FileText, Layers, Eye,
  GitBranch, Zap, Database, AlertTriangle, Clock, Activity, Bell, Cpu, Command, Bot,
} from "lucide-react";

// Methodology-first navigation. Operations/Admin groups preserve existing tabs.
export const SIDEBAR = [
  { g: "", items: [["dashboard", "Mission Control", Gauge]] },
  { g: "Target", items: [["intake", "Intake", Target], ["scope", "Scope", Shield]] },
  { g: "Recon", items: [["passive", "Passive Recon", Radar], ["active", "Active Recon", Crosshair], ["urls", "URL Collection", Globe], ["js", "JavaScript Mining", FileText]] },
  { g: "Map", items: [["surface", "Asset Map", Layers], ["fingerprint", "Tech Fingerprint", Eye], ["params", "Parameters", GitBranch]] },
  { g: "Test", items: [["xss", "XSS", Zap], ["sqli", "SQLi", Database], ["auth", "Auth / API", Shield], ["takeover", "Subdomain Takeover", Globe]] },
  { g: "Methodology", items: [["ai-api-fuzzing", "AI API Fuzzing", Bot]] },
  { g: "Evidence", items: [["findings", "Findings", AlertTriangle], ["timeline", "Timeline", Clock]] },
  { g: "Report", items: [["export", "Export", FileText]] },
  { g: "Operations", items: [["jobs", "Jobs", Activity], ["monitors", "Monitors", Bell], ["resources", "Resources", Cpu]] },
];

export const RAIL = ["Target", "Scope", "Passive", "Active", "Map", "Test", "Evidence", "Report"];

// Mirrors AGENT_CHAIN in main.py (scope_guard -> ... -> reporter).
export const AGENTS = [
  { name: "scope_guard", label: "Scope Guard", icon: Shield, desc: "scope gate" },
  { name: "strategist", label: "Strategist", icon: GitBranch, desc: "attack plan" },
  { name: "recon", label: "Recon", icon: Radar, desc: "surface map" },
  { name: "hunter", label: "Hunter", icon: Crosshair, desc: "probe + test" },
  { name: "analyst", label: "Analyst", icon: Eye, desc: "triage + cvss" },
  { name: "reporter", label: "Reporter", icon: FileText, desc: "draft report" },
];

// Allowed testing level. Frontend-only classification per the redesign spec:
// it labels workflows and gates UI warnings; it does NOT change command
// semantics or trigger any scan. [id, label, hint].
export const RISK_MODES = [
  ["passive", "Passive Only", "No traffic to the target — OSINT, archives, certificate logs."],
  ["passive_active", "Passive + Active", "Adds resolution, probing, crawling. Sends traffic to the target."],
  ["full", "Full Exploitation", "Includes aggressive workflows — fuzzing, XSS, SQLi, exploitation."],
];

// Methodology workspaces. Each maps a sidebar route to a set of kill-chain
// phase ids (from PIPELINE_PHASES in main.py) that the Command Forge renders
// for the active target. `guide` is the short tactical helper shown when guide
// mode is on. Phase ids must match main.py:_PHASE_BY_ID.
export const PHASE_PAGES = {
  passive: {
    eyebrow: "Recon · Passive",
    title: "Passive Recon",
    sub: "Expand the known surface from public sources before any active probe touches the target.",
    phases: ["scope-check", "passive-enum", "archive-urls"],
    guide: "Passive recon never sends traffic to the target — it mines certificate transparency, archives, and OSINT. Drag it to completion before active probing so you know the full surface you're about to engage.",
  },
  active: {
    eyebrow: "Recon · Active",
    title: "Active Recon",
    sub: "Resolve, fingerprint, and probe the live surface. These workflows send traffic to the target.",
    phases: ["resolve", "tls-cdn", "port-scan", "http-probe", "crawl"],
    guide: "Active recon touches the target. Keep OPSEC defaults — rate limit, jitter, identifying headers — on.",
  },
  urls: {
    eyebrow: "Recon · URLs",
    title: "URL Collection",
    sub: "Harvest historical and crawled URLs to seed parameter and endpoint discovery.",
    phases: ["archive-urls", "crawl"],
    guide: "Archived URLs are free signal — they surface dead endpoints, old parameters, and forgotten hosts the live site no longer links.",
  },
  js: {
    eyebrow: "Recon · JavaScript",
    title: "JavaScript Mining",
    sub: "Pull and analyze JS for endpoints, secrets, and reconstructable source maps.",
    phases: ["js-analyze", "secrets"],
    guide: "JS bundles leak routes and keys. Parse with an AST (jsluice) before regex — fewer false positives, and you catch dynamically-built URLs.",
  },
  params: {
    eyebrow: "Map · Parameters",
    title: "Parameter Inventory",
    sub: "Discover hidden and archived parameters to expand the injectable surface.",
    phases: ["param-discovery", "pattern-filter"],
    guide: "Every undocumented parameter is attack surface. Diff behavior (arjun/x8) to find params the docs never mention, then bucket them by sink with gf.",
  },
  fingerprint: {
    eyebrow: "Map · Fingerprint",
    title: "Tech Fingerprint",
    sub: "Identify stacks, WAFs, and CDNs to tailor the next probes.",
    phases: ["tls-cdn", "http-probe"],
    guide: "Fingerprint before you fuzz. Knowing the WAF vendor and origin stack tells you which payloads are worth sending and which will just burn rate limit.",
  },
  xss: {
    eyebrow: "Test · Cross-Site Scripting",
    title: "XSS",
    sub: "Reflection discovery and DOM / parameter XSS verification.",
    phases: ["xss-targeted"],
    risk: "aggressive",
    guide: "Find reflections first (gxss), then verify with dalfox. Confirm a working PoC in a real browser before reporting — parsers disagree; the runtime wins.",
  },
  sqli: {
    eyebrow: "Test · SQL Injection",
    title: "SQLi",
    sub: "SQL injection — from detection differential to data, files, and command execution.",
    phases: ["sqli"],
    risk: "aggressive",
    guide: "Provoke a differential the DB can't hide — error, boolean, or timing — confirm the injection, then escalate: dump the schema, read/write files, and pivot to command execution where the stack allows.",
  },
  auth: {
    eyebrow: "Test · Auth / API",
    title: "Auth / API",
    sub: "Probe authentication flows and API surfaces — GraphQL, REST, JWT.",
    phases: ["http-probe", "vuln-scan"],
    guide: "APIs are where the critical bugs live. Map every resolver/route, then test object-level authorization (IDOR) on each mutation that takes an id.",
  },
  takeover: {
    eyebrow: "Test · Subdomain Takeover",
    title: "Subdomain Takeover",
    sub: "Hunt dangling CNAMEs and unclaimed services across the resolved surface.",
    phases: ["resolve", "vuln-scan"],
    guide: "A CNAME pointing at an unclaimed service is a takeover. Prove you can serve content on the host before reporting — a fingerprint match alone is not evidence.",
  },
};

export const PALETTE_ACTIONS = [
  ["Go to Mission Control", "nav", Gauge, "dashboard"],
  ["Load target", "target", Target, "intake"],
  ["Validate scope", "scope", Shield, "scope"],
  ["Go to Passive Recon", "recon", Radar, "passive"],
  ["Go to Active Recon", "recon", Crosshair, "active"],
  ["Generate XSS commands", "cmd", Zap, "xss"],
  ["Generate SQLi commands", "cmd", Database, "sqli"],
  ["Open AI API Fuzzing methodology", "method", Bot, "ai-api-fuzzing"],
  ["Open Findings board", "evidence", AlertTriangle, "findings"],
  ["Open Asset Map", "map", Layers, "surface"],
  ["Export to vault", "export", FileText, "export"],
  ["View Monitors", "ops", Bell, "monitors"],
];
