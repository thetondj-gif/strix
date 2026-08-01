# Strix licence disposition

## Verified repository state

The repository is licensed under **Apache License 2.0**.

## Wave 1 decision

DAWN may retain or adapt Apache-2.0-licensed source provided applicable copyright, licence and NOTICE requirements are preserved. The licence does not provide authority to test systems.

## Required before any security canary

Record:

1. written authority from the system owner;
2. exact target, host and environment;
3. allowed and prohibited methods;
4. test window and rate limits;
5. evidence handling and redaction policy;
6. stop conditions and emergency contact;
7. data-retention and deletion plan;
8. remediation and retest procedure.

Production or customer targets remain prohibited during the initial canary. Use only an isolated application owned and controlled by the operator.

## Merge gate

The scope validator, fixtures and offline acceptance check may become technically merge-ready when CI and the Mac pull-and-test pass. Merging does not authorise a scan or enable a runtime.
