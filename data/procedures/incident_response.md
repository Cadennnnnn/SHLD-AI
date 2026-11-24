
# Simulated Security Incident Response Procedure

## Purpose

Provide a consistent process for investigating simulated cybersecurity alerts.

## Initial Investigation

1. Record the incident identifier and the time the alert was received.
2. Retrieve available security events associated with the incident.
3. Identify affected assets, accounts, source addresses, and event timestamps when present in the evidence.
4. Distinguish confirmed observations from hypotheses.
5. Document missing evidence before recommending further investigation.

## Severity Assessment

- Critical: Evidence indicates an ongoing, high-impact compromise.
- High: Multiple indicators suggest a significant compromise.
- Medium: Suspicious activity requires additional investigation.
- Low: Limited suspicious activity with no confirmed impact.

Severity must be based on recorded evidence. Do not assign severity solely from an alert title.

## Containment Recommendations

1. Identify the affected asset and supporting evidence.
2. Consult the applicable containment procedure.
3. Describe the proposed action and its expected impact.
4. Obtain explicit human approval before any containment action.
5. Record the approval and the outcome.
6. Never claim an action was executed without confirmation.

## Evidence and Reporting

- Cite the source of each material finding.
- Separate facts, hypotheses, and unknowns.
- If evidence is insufficient, state that limitation.
- Do not invent logs, timestamps, IP addresses, affected assets, or outcomes.
- Record the investigation plan and the next recommended step.
