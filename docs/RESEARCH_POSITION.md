# MRMA research position

MRMA is an evidence-driven HTTP trust-boundary experimentation framework.

Its central question is deliberately narrower than a generic web scanner:

> Which attacker-controlled request property reproducibly influences behavior across an HTTP
> trust boundary, and what is the smallest input that preserves that influence?

This document records the adjacent-tool study behind that position. It is a product boundary,
not a claim that the listed tools cannot be extended beyond their documented primary workflows.

## Adjacent systems

| System | Documented strength | Boundary MRMA should own |
|---|---|---|
| [Burp Repeater, Intruder, and Comparer](https://portswigger.net/burp/documentation/desktop/tools) | Manual replay, configurable attacks, and visual response comparison | Automated repeated experiments with explicit controls and machine-readable evidence |
| [Param Miner](https://github.com/PortSwigger/param-miner) | Hidden header/parameter discovery using advanced diffing and binary search | Quantifying a known input's reproducibility, rejecting unstable targets, and minimizing under the same evidence oracle |
| [AutoRepeater](https://github.com/nccgroup/AutoRepeater) | Automated replacement, resend, and original/modified diff workflows | Counterbalanced experiment design and confidence-aware verdicts |
| [ZAP Fuzzer](https://www.zaproxy.org/docs/desktop/addons/fuzzer/) | General payload generation and scripted request fuzzing | Trust-boundary hypotheses rather than broad payload enumeration |
| [Nuclei HTTP fuzzing](https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview) | Declarative, scalable rules, matchers, and multi-part HTTP fuzzing | Target-specific behavioral inference without requiring a vulnerability template |
| [mitmproxy](https://docs.mitmproxy.org/stable/overview/features/) | Programmable interception, transformation, recording, and replay | A built-in experimental method and evidence model |
| [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) | High-throughput and complex request sequences with a custom stack | Low-rate, control-heavy research where reproducibility matters more than throughput |
| [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) | Root-cause parser-discrepancy detection for desynchronization classes | Broader application, routing, identity, cache, and authorization trust influence |
| [HTTP Garden](https://arxiv.org/abs/2405.17737) and [Gudifu](https://www.onarlioglu.com/publications/raid2024gudifu.pdf) | Differential fuzzing of HTTP implementations and parser discrepancies | Black-box experiments against deployed multi-layer behavior, with bounded conservative defaults |
| [Delta Debugging](https://www.st.cs.uni-saarland.de/papers/tse2002/) | Automated isolation of minimal failure-inducing input | A stability-aware change oracle specialized for HTTP trust boundaries |

## The MRMA method

MRMA should treat every finding as an experiment, not an anomaly row:

1. State a request-property hypothesis.
2. Capture repeated unchanged controls.
3. Bracket each mutation with local controls, or explicitly select a seeded balanced schedule.
4. Normalize only declared volatile fields.
5. Reject the run when controls are unstable.
6. Report reproducibility, uncertainty, and the concrete signals that changed.
7. Minimize the responsible input using the same repeated oracle.
8. Export a versioned evidence object that another engineer can replay and audit.

Version 0.4.2 implements steps 1-6 for a single mutation in `mrma experiment`, including explicit
state and connection modes, fixed-sample confidence decisions, canonical redirect and field-aware
header semantics, ambiguity-preserving cache comparison, typed retry subtypes, multidimensional
assurance, bounded observations, authorization, central budgets, recoverable evidence, and manual
redirects. Existing isolation and profile commands use the same network policy kernel but remain
exploratory and do not yet use this fixed-sample oracle.

## Defensible differentiation

The memorable product is not "a header fuzzer with nicer output." It is:

**An experimental instrument for mapping request-property influence across layered HTTP systems.**

The long-term research object is a Trust Influence Graph:

- Input nodes: headers, pseudo-headers, method, path, query, body fields, framing, and protocol.
- Boundary nodes: CDN, WAF, gateway, proxy, cache, router, framework, and application policy.
- Outcome nodes: routing, identity, authorization, caching, redirects, content, and timing.
- Evidence edges: reproducibility, control stability, effect size, minimal trigger, transport, and
  manual-validation state.

That graph must be derived from evidence. MRMA must never infer which proprietary component made
a decision when black-box observations cannot establish it.

## Engineering principles

- No severity score without a validated model. Influence, reproducibility, and impact remain
  separate dimensions.
- No "raw" label for requests normalized by a general HTTP library. Results declare their
  transport mode.
- No positive verdict from one baseline and one mutation.
- No hidden normalization. The effective policy is part of result metadata; potentially sensitive
  regex literals are HMAC-fingerprinted unless forensic evidence is explicitly selected.
- No mutation values, URL credentials, query strings, or raw response-header values in default
  evidence artifacts; sensitive fields are omitted or fingerprinted.
- No active testing outside targets the operator is authorized to assess.
