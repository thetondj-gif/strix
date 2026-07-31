# DAWN Application Assurance — Capability Foundry Wave 1

## Status

`CAPABILITY_RESEARCH_COMPLETE`

This branch creates no authority to test any live, customer or third-party system.

## Objective

Prepare an isolated security-assurance adapter for explicitly authorised websites and applications. The product outcome is an evidence-backed finding, remediation plan and controlled retest—not autonomous unrestricted exploitation.

## Mandatory task contract

Every future test must include:

- authorised target and owner;
- exact scope and excluded assets;
- permitted techniques;
- time window;
- request and concurrency limits;
- data-retention and redaction policy;
- stop conditions;
- named approver;
- rollback or recovery route.

## First implementation slice

1. Define the authorised-security-test input schema.
2. Add fail-closed target and scope validation.
3. Create an isolated test-target fixture.
4. Add evidence redaction and bounded-output controls.
5. Add tests proving unapproved targets and destructive operations are refused.
6. Map validated findings into DAWN's standard response envelope.

## Wave 1 boundary

No internet-wide discovery, unsanctioned scanning, credential capture, destructive exploitation, persistence, customer production testing or live DAWN activation is permitted.

## Connection gate

The adapter may become connection-ready only after authorised-target enforcement, isolated acceptance tests, licence review, evidence schemas, operational runbook and exact rollback instructions are complete.
