// Per-vuln methodology playbooks. These AUGMENT the existing command pages:
// keyed by the same route ids as PHASE_PAGES (xss, sqli, auth, takeover), they
// add the narrative depth (overview, detection signals, how-to-test steps,
// variant cards, chaining, confirm-before-report) that PhaseWorkspace renders
// around its Command Forge. Distilled from this repo's own doctrine
// (docs/HUNTING_PLAYBOOK.md + agents/playbooks/*), not invented. Display-only.
//
// Shape: { intro, signals[], method[{num,label,summary,points,note?,tools?}],
//          patterns[{title,text,action}], chain[], confirm:{pitfalls[],checklist[]}, refs[] }
export const VULN_PLAYBOOKS = {
  // ── XSS ─────────────────────────────────────────────────────────
  xss: {
    intro:
      `Treat reflected HTML XSS as a starting point, not the prize. The high-payout XSS is JavaScript-context — a parameter reflected into a <script> block, a DOM sink, or a postMessage handler — and above all stored XSS that renders in an admin-visible view. Find the reflection, pin its exact context, then build the payload the context actually needs.`,
    signals: [
      `Parameters reflected into the response without context-correct encoding (HTML body, tag attribute, JS string, URL).`,
      `DOM sinks in the JS bundle: innerHTML, document.write, eval, setTimeout(string), location assignment, jQuery .html().`,
      `Sources that feed those sinks: location.hash / location.search, document.referrer, postMessage, window.name.`,
      `Stored-input fields rendered later: comment, bio, note, message, review, profile, display-name.`,
      `A weak or missing CSP — or a CSP whose allowlist includes a JSONP/CDN bypass (jsdelivr, unpkg, cdnjs).`,
    ],
    method: [
      { num: "01", label: "Pin the reflection context", summary: "Where exactly does input land? The context dictates the payload.",
        points: [
          `Reflect a unique marker (e.g. rf0xCAFE) and locate every echo in the response.`,
          `Classify each: HTML body, attribute (quoted/unquoted), <script> string, HTML comment, or DOM sink.`,
          `Don't reach for <script>alert(1) — break out of the actual context first (close the attribute/string/tag).`,
        ] },
      { num: "02", label: "Audit the CSP before you commit", summary: "A reflection under a strict CSP may be unexploitable; under a weak one it's a one-click bug.",
        points: [
          `Read the Content-Security-Policy header and any meta CSP.`,
          `Flag unsafe-inline, unsafe-eval, missing object-src, and overly broad script-src allowlists.`,
          `If blocked, document the exact bypass primitive you'd need — that is part of the finding.`,
        ],
        note: { kind: "tip", text: `ReconForge's xss-deep pass adds a CSP audit that flags weak directives which turn a reflected XSS into a working alert(1).` } },
      { num: "03", label: "Trace DOM source → sink", summary: "DOM XSS lives entirely client-side — the server never sees the payload.",
        points: [
          `Follow taint from source to sink with DOM Invader (or jsluice's source-sink extraction).`,
          `Prefer sinks that fire without interaction (hash-driven render on load) — no click required is a severity bump.`,
          `Confirm the data path in the running page, not just by reading minified JS.`,
        ] },
      { num: "04", label: "Confirm in a real browser", summary: "Parsers disagree; the runtime is the truth.",
        points: [
          `Execute the payload in an actual browser — a curl dump that contains your string is not proof of execution.`,
          `Capture a screenshot of the rendered alert/exfil plus the console output.`,
          `For stored XSS, confirm the payload persists across sessions and renders in the target view (ideally admin-rendered).`,
        ] },
    ],
    patterns: [
      { title: "Reflected, no CSP", text: `Input echoed into the page with no encoding and no CSP to stop it; single-click trigger.`,
        action: `High when interaction is one click — build the context-correct breakout and confirm in-browser.` },
      { title: "Stored in admin-rendered view", text: `Payload saved via a user field (bio/comment/ticket) that an admin later views in a privileged context.`,
        action: `Highest payout — render-to-admin = admin session hijack. Prove it lands in the admin view; this is Critical.` },
      { title: "DOM-based, zero interaction", text: `Sink fires on load from location.hash/name — no server reflection, often bypasses server-side filters.`,
        action: `Trace source→sink with DOM Invader; demonstrate the trigger on page load.` },
      { title: "CSP bypass via allowlist", text: `CSP present but script-src allows a CDN that can serve attacker-controllable JS / JSONP.`,
        action: `Analyze the allowlist for jsdelivr/unpkg/cdnjs/JSONP endpoints; document the exact bypass.` },
      { title: "Self-XSS — not a finding alone", text: `Only triggerable in the victim's own input; $0 standalone.`,
        action: `Chain it: self-XSS + CSRF + stored render to admin = account takeover.` },
    ],
    chain: [
      `Self-XSS + weak CSRF + a stored render to an admin = admin session takeover (scripts/chain/selfxss-csrf-stored.sh).`,
      `XSS + a non-HttpOnly auth cookie = direct session theft.`,
      `Stored XSS that bypasses CSRF protection escalates both — report the chain, and CVSS the chain, not the weakest link.`,
    ],
    confirm: {
      pitfalls: [
        `A string appearing in the response is not execution — confirm it actually runs in a browser.`,
        `Don't report self-XSS as standalone; either chain it or drop it.`,
        `If a CSP fully blocks the payload and you have no bypass, it's informational at most — say so honestly.`,
      ],
      checklist: [
        `Reflection context identified (HTML / attribute / JS / DOM sink).`,
        `CSP read and any required bypass primitive documented.`,
        `Payload executes in a real browser (screenshot + console captured).`,
        `For stored: persistence and the rendering view confirmed (admin context noted).`,
        `Cookie HttpOnly/SameSite state recorded; chain potential assessed.`,
      ],
    },
    refs: [
      `agents/playbooks/manual/xss.md — manual verification checklist`,
      `docs/HUNTING_PLAYBOOK.md → XSS deep dive (CSP audit, DOM-sink mining, stored candidates)`,
      `Command Forge below runs gxss (reflection discovery) → dalfox (verification).`,
    ],
  },

  // ── SQLi ────────────────────────────────────────────────────────
  sqli: {
    intro:
      `SQLi turns a query parameter into a foothold. Provoke a differential the database can't hide — an error, a boolean flip, or a timing delay — confirm the injection, then escalate: enumerate the schema, dump data, read and write files, and where the stack allows, pivot to command execution.`,
    signals: [
      `Parameters that reach a query: search, filter, sort, id, category, where-like params, and JSON body fields.`,
      `Error responses that leak SQL fragments, driver names, or stack traces on malformed input.`,
      `gf-sqli bucketed candidates from the URL corpus.`,
      `ORDER BY / LIMIT / column-name params (often concatenated, not parameterized).`,
      `GraphQL resolver arguments (filter/search) that feed a backend query.`,
    ],
    method: [
      { num: "01", label: "Confirm the injection", summary: "Prove a syntax-driven differential before automating.",
        points: [
          `Error-based: send a single quote / unbalanced syntax and watch for SQL errors.`,
          `Boolean-based: compare ' AND 1=1 vs ' AND 1=2 responses for a content difference.`,
          `Time-based: a sleep primitive that delays the response confirms blind injection.`,
          `Fingerprint the DBMS from error strings / behavior to pick the right syntax.`,
        ] },
      { num: "02", label: "Enumerate & dump", summary: "Map the database, then pull what matters.",
        points: [
          `sqlmap --dbs --tables --columns to map; --dump to extract target tables.`,
          `UNION-based: match column count/types, then read arbitrary tables via information_schema.`,
          `Prioritize credential, token, and PII tables — they're the pivot fuel.`,
          `Run --batch with your configured rate limit so the traffic stays controlled.`,
        ] },
      { num: "03", label: "Escalate to the host", summary: "Turn the injection into files and shells where the engine allows.",
        points: [
          `File read/write: sqlmap --file-read / --file-write (MySQL INTO OUTFILE, MSSQL, PostgreSQL).`,
          `Command execution: --os-shell / --os-pwn; MSSQL xp_cmdshell; stacked queries where the driver allows multiple statements.`,
          `Write a webshell to a known web root, or harvest secrets to pivot to other services.`,
          `Capture the exact request, injection point, and the proof (dumped row / file / shell).`,
        ],
        note: { kind: "tip", text: `ReconForge's SQLi phase (17-sqli.sh) wraps sqlmap; scope_guard still constrains live execution to declared targets.` } },
    ],
    patterns: [
      { title: "Error-based", text: `The app returns DB errors that change with injected syntax.`,
        action: `Fastest confirmation; extract via the error channel where supported. Screenshot the error delta.` },
      { title: "Boolean-blind", text: `No errors, but true/false conditions change the response body.`,
        action: `Build a reliable true/false oracle, then enumerate one bit at a time (sqlmap automates this).` },
      { title: "Time-blind", text: `No content or error differential — only response timing leaks the boolean.`,
        action: `Use a sleep payload; account for jitter with repeated measurements before claiming.` },
      { title: "UNION-based", text: `Injectable into a SELECT where you can append a UNION of attacker-chosen columns.`,
        action: `Match column count/types, then read arbitrary tables via information_schema.` },
      { title: "Stacked → RCE", text: `Where the driver allows multiple statements, chain writes / xp_cmdshell / INTO OUTFILE.`,
        action: `Confirm command execution or a written webshell — the high-impact outcome.` },
      { title: "GraphQL resolver injection", text: `A GraphQL filter/search argument is concatenated into a backend SQL/NoSQL query.`,
        action: `Test every resolver that takes a filter — High–Critical. See Auth / API and the AI API Fuzzing methodology.` },
    ],
    chain: [
      `SQLi that reads credentials/session tokens → account takeover.`,
      `SQLi → --file-write a webshell → RCE → foothold for post-exploitation.`,
      `SQLi exposing cloud/service config → pivot to internal services.`,
      `On GraphQL, resolver SQLi often pairs with mutation IDOR — map the schema first.`,
    ],
    confirm: {
      pitfalls: [
        `A generic 500 is not SQLi — prove a syntax-driven differential (error / boolean / time).`,
        `Time-based hits need repeated measurements — one slow response is jitter, not proof.`,
        `Record the DBMS and exact injection point; a payload without its context isn't reproducible.`,
      ],
      checklist: [
        `Injection confirmed via a reproducible differential (error / boolean / time).`,
        `DBMS identified; injection point and parameter recorded.`,
        `Impact demonstrated and captured (dumped row / file read or write / shell).`,
        `Pivot value assessed (creds, tokens, config, host access).`,
      ],
    },
    refs: [
      `docs/HUNTING_PLAYBOOK.md → per-vuln deep dives + chaining`,
      `Command Forge below runs the sqlmap phase (17-sqli.sh).`,
    ],
  },

  // ── Auth / API ──────────────────────────────────────────────────
  auth: {
    intro:
      `APIs are where the critical bugs live. Map every route and resolver, then test object- and function-level authorization on each — most API bugs are "the server checks you're logged in, but not that you own the thing." This page covers IDOR/BOLA, broken function-level access, JWT flaws, GraphQL authorization, and mass assignment. For the LLM-driven, at-scale version, see the AI API Fuzzing methodology.`,
    signals: [
      `Numeric IDs, UUIDs, or slugs in paths/params (/users/1234, ?orderId=...).`,
      `User-scoped endpoints: /me, /profile, /account, anything returning your own data by id.`,
      `GraphQL mutations whose names imply object identity: createOrUpdate*, delete*, transfer*.`,
      `JWT bearer tokens or session cookies; login / SSO / OAuth callback flows.`,
      `Create/update endpoints that accept a JSON body (mass-assignment surface).`,
      `Admin-only paths behind a thin gate (good broken-access targets).`,
    ],
    method: [
      { num: "01", label: "Two-account differential (IDOR/BOLA)", summary: "The core API authz test — run it across two accounts you control.",
        points: [
          `Capture a request as Account A; identify the object id (numeric / UUID / slug).`,
          `Replay as Account B, swapping in A's id; compare status, length, and body.`,
          `Repeat with another id to rule out a one-off; for writes, confirm the change persisted from A's session.`,
          `Record raw request/response pairs for both accounts.`,
        ],
        note: { kind: "tip", text: `Use two accounts you control (A as victim, B as attacker) so the differential is clean and repeatable.` } },
      { num: "02", label: "Function-level / broken access", summary: "Can a low-priv (or anonymous) caller reach privileged functions?",
        points: [
          `Replay admin-only requests with a standard-user (or no) token.`,
          `Try header bypasses: X-Original-URL / X-Rewrite-URL, X-Forwarded-For: 127.0.0.1, X-HTTP-Method-Override: DELETE.`,
          `Try path tricks: case (/Admin), trailing/double slash, encoded segments.`,
        ] },
      { num: "03", label: "JWT inspection", summary: "If the auth is a JWT, test how it's validated.",
        points: [
          `alg:none — strip the signature, change claims, resubmit.`,
          `Algorithm confusion — re-sign an RS256 token with the public key as an HMAC (HS256) secret.`,
          `Weak secret — for HS256, run hashcat -m 16500 against the captured token.`,
          `exp handling — replay an expired token; also check kid injection and jku/x5u SSRF.`,
        ] },
      { num: "04", label: "GraphQL authorization", summary: "Map the schema, then test every resolver for ownership checks.",
        points: [
          `Check introspection ({ __schema { types { name } } }); if off, reconstruct via clairvoyance and enumerate with InQL.`,
          `For every *Update*/*Create*/delete*/transfer* mutation, test object ownership — mutation IDOR is the top-paying flavor.`,
          `Check alias batching (many aliased ops in one request) for per-query authz gaps and DoS.`,
        ] },
      { num: "05", label: "Mass assignment", summary: "Bind fields the server discloses but doesn't expect as input.",
        points: [
          `Diff the response shape against the accepted request body.`,
          `Add ONE privileged field at a time: role, isAdmin, permissions, plan, tier, verified, organizationId, ownerId, balance.`,
          `Use harmless values first (role:"test"); escalate only after the server accepts it, on owned accounts only.`,
        ] },
    ],
    patterns: [
      { title: "Mutation IDOR (GraphQL)", text: `A mutation authorizes that you can call it, but not that you own the object id it touches.`,
        action: `Highest API payout — test every id-taking mutation; pair with the graphql-mass-assign chain.` },
      { title: "Cross-tenant object access", text: `Account A in org X reads or writes an object belonging to org Y.`,
        action: `Escalate to Critical — cross-tenant is a systemic authz failure, not a single leak.` },
      { title: "alg:none / algorithm confusion", text: `Server trusts an unsigned token, or an RS256 token re-signed with the public key as HMAC.`,
        action: `Forge a token with elevated claims; demonstrate access as another user → account takeover.` },
      { title: "Mass-assignment privesc", text: `An update endpoint accepts isAdmin/role/plan it never intended to expose.`,
        action: `Flip a privilege on your OWN account; capture before/after. Cross-tenant or billing fields = highest severity.` },
      { title: "Header-based access bypass", text: `X-Original-URL / X-Forwarded-For / method-override reaches an admin function past the front gate.`,
        action: `Confirm the privileged action actually executes — not just a 200.` },
    ],
    chain: [
      `IDOR that writes a URL field the server later fetches = SSRF-as-victim (scripts/chain/idor-ssrf.sh).`,
      `Open redirect on an OAuth redirect_uri allowlist domain = account takeover (open-redirect-oauth.sh).`,
      `JWT forgery + an admin endpoint = full admin takeover.`,
      `An IDOR leaking an id→email map becomes a primitive for deanonymization or targeted ATO.`,
    ],
    confirm: {
      pitfalls: [
        `Enumerability alone isn't impact — confirm you actually read or affected another account's data.`,
        `Confirm the cross-account read with a field only the victim account should see — not just a 200.`,
        `A 200 on a bypass header isn't proof — confirm the privileged action really happened.`,
        `One bug = one report; dedupe the same authz flaw across many endpoints.`,
      ],
      checklist: [
        `Two accounts you control ready (A victim, B attacker).`,
        `Cross-account access/mutation reproduced and captured (A↔B request/response).`,
        `For writes: persistence verified from the victim account's own session.`,
        `Token/authz mechanism documented (cookie / JWT / GraphQL resolver).`,
        `Impact framed in business terms (whose data, what action, blast radius).`,
      ],
    },
    refs: [
      `agents/playbooks/manual/idor.md, mass_assignment.md — verification checklists`,
      `agents/playbooks/jwt.md, graphql.md — class-specific signals`,
      `AI API Fuzzing workspace — LLM-driven, at-scale BAC/IDOR`,
      `docs/HUNTING_PLAYBOOK.md → IDOR / GraphQL / JWT / broken-access dives`,
    ],
  },

  // ── Subdomain Takeover ──────────────────────────────────────────
  takeover: {
    intro:
      `A subdomain whose DNS still points at an unclaimed third-party service can be claimed by anyone — including you. ReconForge flags candidates deterministically (CNAME signature + "not found" fingerprint); the finding is only real once you prove you can serve your own content on the victim subdomain. Serve a benign proof — never phishing.`,
    signals: [
      `CNAME pointing at a third-party service that allows unauthenticated claim (GitHub Pages, S3, Heroku, Fastly, Shopify, Azure, Netlify, Surge, Firebase).`,
      `HTTP body showing the provider's "no such site / not found / unclaimed" page.`,
      `Dangling CNAMEs to decommissioned internal hosts.`,
      `NS records delegated to a provider account that no longer exists.`,
      `Subdomains in the auth cookie scope, OAuth callback hosts, or email/DKIM senders (severity multipliers).`,
    ],
    method: [
      { num: "01", label: "Confirm the dangle", summary: "Verify the CNAME target is actually claimable and currently unowned.",
        points: [
          `Resolve the full CNAME chain and identify the terminating provider.`,
          `Confirm the provider serves a "not found / unclaimed" signature, not a real site.`,
          `Match the provider against the known-vulnerable service list before attempting a claim.`,
        ] },
      { num: "02", label: "Claim and serve a benign proof", summary: "Register the resource and prove control — minimally.",
        points: [
          `Register the resource on the third-party service (e.g. the GitHub Pages repo / the S3 bucket name).`,
          `Serve a researcher-controlled HTML file with a timestamp and your handle — nothing else.`,
          `Verify the proof is reachable via the victim subdomain over HTTPS.`,
        ],
        note: { kind: "warn", text: `Do NOT serve phishing, credential prompts, or any content beyond a benign proof. The screenshot is the trophy — stop there, then tear the resource down.` } },
      { num: "03", label: "Assess blast radius", summary: "Where the subdomain sits decides the severity.",
        points: [
          `Is it inside the parent-domain auth cookie scope? → session-hijack potential.`,
          `Does it host auth / OAuth callbacks? → login-flow abuse.`,
          `Is it in an email-sender / DKIM context? → spoofing / phishing infrastructure.`,
        ] },
    ],
    patterns: [
      { title: "GitHub Pages / S3 / Netlify", text: `CNAME → provider, provider shows an unclaimed page; the resource name is free to register.`,
        action: `Claim the exact resource name; serve the timestamped proof file.` },
      { title: "In-cookie-scope takeover", text: `The hijackable subdomain shares the parent domain's cookie scope.`,
        action: `Escalate — a takeover here enables session hijack (scripts/chain/takeover-chain.sh). Critical.` },
      { title: "OAuth / auth-callback host", text: `The subdomain hosts authentication or OAuth callbacks.`,
        action: `Controlling it can intercept tokens/codes — frame the login-flow impact explicitly.` },
      { title: "Email / DKIM context", text: `The subdomain appears in SPF/DKIM/sender configuration.`,
        action: `Takeover enables convincing phishing from a trusted name — note the email-spoofing impact.` },
    ],
    chain: [
      `Takeover + a parent-domain-scoped cookie = session hijack (scripts/chain/takeover-chain.sh).`,
      `Takeover of an OAuth callback host = token/code interception → account takeover.`,
      `Takeover of a DKIM/sender host = trusted-origin phishing infrastructure.`,
    ],
    confirm: {
      pitfalls: [
        `A fingerprint match alone is not a finding — you must serve content on the subdomain to prove it.`,
        `Serve only a benign proof; phishing / credential pages are out of bounds and unethical.`,
        `Tear down the claimed resource after capturing evidence; don't leave it live.`,
      ],
      checklist: [
        `Full CNAME chain captured; provider identified as claimable.`,
        `Provider confirmed to serve an unclaimed / not-found page.`,
        `Benign timestamped proof served and reached via the victim subdomain (screenshot).`,
        `Cookie-scope / OAuth / DKIM context assessed for severity.`,
        `Claimed resource cleaned up after evidence capture.`,
      ],
    },
    refs: [
      `agents/playbooks/manual/takeover.md — manual verification + "serve benign proof" rule`,
      `docs/HUNTING_PLAYBOOK.md → Subdomain takeover + takeover-chain`,
      `Command Forge below runs resolve + nuclei takeover templates.`,
    ],
  },
};
