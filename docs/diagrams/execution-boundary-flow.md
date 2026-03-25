# Execution Boundary Flow

```text
+-----+     +-------+     +--------------+     +----------------------+
| LLM | --> | Skill | --> | Tool Request | --> | Policy Enforcement   |
+-----+     +-------+     +--------------+     | Layer                |
  ^                                             +----------------------+
  |                                                       |      |
  |                                                    ALLOW    DENY
  |                                                       |      |
  |                                                       v      v
  |                                              +----------+  +------------------+
  +<------- (Decision returned to caller) <------| Execute  |  | Block + Trace ID |
                                                 +----------+  +------------------+
                                                       |              |
                                                       v              v
                                                 (proceed)    (retry / escalate /
                                                               abort gracefully)
```

The policy enforcement layer sits between workflow intent and execution. Its role is to evaluate
the request before side effects occur and return a deterministic ALLOW or DENY based on policy,
authorization, validation, and risk checks.

Both decisions — ALLOW and DENY — are returned to the calling layer as `Decision` objects so
the orchestrator can reason about the outcome: proceed with results, retry with different
parameters, request user escalation, or abort gracefully. DENY is not a terminal state — it is
a signal the orchestrator acts on.
