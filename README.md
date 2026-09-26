# Cloud Remediation MVP

A cloud security remediation control plane designed to transform security findings into governed, executable, and verifiable remediation workflows.

## Overview

Cloud environments generate security findings across infrastructure, identities, networks, and services. Identifying a security issue is only the beginning of the remediation process. Organizations must also determine which resource is affected, who owns it, how it is managed, what remediation is appropriate, whether the change requires approval, and whether the issue has actually been resolved.

Cloud Remediation MVP explores an approach to addressing this challenge by connecting security findings with resource inventory, remediation decision-making, governance, controlled execution, and independent verification.

The platform is designed around a cloud-agnostic architecture, with AWS serving as the initial implementation environment.

## Initial Project Scope

The initial development milestone establishes the AWS S3 security baseline and the foundation for a remediation workflow.

The initial scope includes:

- Establishing an AWS S3 security baseline.
- Defining infrastructure configuration through Terraform.
- Creating the foundation for identifying and addressing cloud security misconfigurations.

## Project Direction

The project aims to advance a risk-governed remediation lifecycle:

1. Detect security findings.
2. Normalize findings and identify affected resources.
3. Determine resource ownership and management context.
4. Assess risk and select appropriate remediation.
5. Establish governance and approval requirements.
6. Execute authorized remediation.
7. Independently verify the resulting configuration.
8. Reconcile the outcome with the original security finding.

The initial implementation focuses on AWS. Support for additional cloud providers is a longer-term architectural objective, not a claim of current multi-cloud implementation.

## Technology Stack

- Amazon Web Services (AWS)
- Terraform
- Python
- Git

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.


## Security Hub Integration and Resource Inventory

The next development milestone introduced integration with AWS Security Hub to retrieve cloud security findings and connect them with an inventory of discovered AWS resources.

This established an important foundation for the remediation platform: security findings need to be associated with identifiable infrastructure resources before meaningful remediation decisions can be made.

The implementation introduced:

- A Python-based AWS Security Hub findings adapter.
- Resource inventory collection for identifying AWS infrastructure.
- Initial integration between security findings and discovered resource information.
- A foundation for determining which infrastructure resources are associated with reported security issues.

This milestone moved the project beyond establishing a security baseline toward building a finding-to-resource identification workflow.

## Synthetic Findings and Remediation Proposal Generation

This milestone introduced a structured approach to developing and testing remediation workflows using synthetic security findings.

Synthetic findings provided a controlled way to evaluate how the platform processes security issues before connecting the workflow to live findings.

The implementation introduced:

- Synthetic AWS S3 security finding fixtures.
- A remediation catalog describing supported remediation actions.
- A proposal generation component that evaluates findings against available remediation definitions.
- Structured remediation proposal output.
- Draft proposal generation with execution disabled by default.

This established the foundation for separating security finding identification from remediation planning. Rather than immediately modifying cloud resources, the platform first produces a structured proposal that can be reviewed and evaluated.

## Real Security Hub Finding Remediation Workflow

This milestone extended the platform from synthetic testing to processing real security findings retrieved from AWS Security Hub.

The objective was to establish a workflow capable of translating an actual cloud security finding into a structured remediation proposal.

The implementation introduced:

- Retrieval and processing of live AWS Security Hub findings.
- Mapping of real findings to supported remediation definitions.
- Identification of affected AWS resources using finding metadata.
- Generation of remediation proposals from real security findings.
- Separation of proposal generation from actual remediation execution.

This milestone represented an important progression toward operational remediation workflows by demonstrating how findings from a cloud security service could become actionable remediation proposals.

## Remediation Governance and Review History

This milestone introduced governance capabilities to establish a review process for remediation proposals before execution.

The objective was to ensure that proposed cloud security changes could be evaluated and documented rather than automatically applied as soon as a finding was identified.

The implementation introduced:

- A dedicated remediation governance component.
- Proposal review and decision tracking.
- Recording of governance outcomes and review history.
- Separation of remediation approval decisions from proposal generation and execution.

This established governance as a distinct stage in the remediation lifecycle, providing a foundation for controlled and auditable remediation operations.

## Expanded Cloud Resource Inventory and Finding Matching

This milestone expanded the platform's resource inventory and improved its ability to associate security findings with identifiable cloud resources.

As the project evolved, it became clear that retrieving security findings alone was insufficient. The platform also needed to understand the affected resources and their management context to support reliable remediation decisions.

The implementation introduced:

- Expanded AWS resource discovery across additional resource types.
- Improved resource identification and finding-to-inventory matching.
- Resource type mapping to normalize differences between Security Hub findings and inventory representations.
- Improved handling of unmatched resource findings and account-level findings.
- Initial identification of infrastructure managed through Terraform.

This milestone strengthened the resource identification layer and established a foundation for determining how affected resources are managed before proposing remediation.

## Controlled Remediation Execution Framework

This milestone introduced the foundation for controlled remediation execution, extending the platform beyond finding identification, resource inventory, proposal generation, and governance.

The objective was to establish a mechanism for executing approved infrastructure changes while maintaining safeguards around the resources being modified.

The implementation introduced:

- A dedicated remediation execution engine.
- Integration with Terraform-based remediation workflows.
- Validation of Terraform plans before execution.
- Explicit proposal identification and authorization requirements.
- Execution controls designed to prevent unreviewed infrastructure changes.
- Execution evidence to support auditability and subsequent verification.

This milestone established controlled execution as a distinct component of the remediation lifecycle, separating the decision to remediate from the actual modification of cloud infrastructure.

## S3 TLS Enforcement Remediation Workflow

This milestone introduced the S3 TLS enforcement remediation workflow, demonstrating how the platform could translate a real AWS security finding into a controlled infrastructure change.

The workflow focused on enforcing secure transport for Amazon S3 bucket access through a Terraform-managed bucket policy.

The implementation and validation included:

- Generation of a remediation proposal from a real S3 security finding.
- Creation and review of a Terraform execution plan before applying changes.
- Validation that the plan contained the expected infrastructure change.
- Controlled execution through the remediation execution engine.
- Direct verification of the resulting S3 bucket policy.
- Recording of execution and verification evidence.

The successful remediation demonstrated that the platform could progress beyond generating proposals and execute a controlled AWS security change, followed by independent configuration verification.

## Remediation Reconciliation and Evidence Validation

This milestone focused on strengthening the reconciliation process to ensure that remediation outcomes are supported by verifiable execution and configuration evidence.

The objective was to establish a reliable mechanism for determining whether a remediation proposal had been successfully executed and whether the resulting cloud configuration satisfied the intended security requirement.

The implementation introduced:

- Validation of execution and verification evidence.
- Correlation of evidence with proposal, finding, resource, account, and region identifiers.
- Chronological validation of execution and verification events.
- Timezone-aware timestamp parsing and validation.
- Verification of remediation outcomes against direct AWS configuration checks.
- Security Hub status reconciliation.
- Explicit application controls and audit evidence for reconciliation operations.

This milestone strengthened the platform's ability to distinguish between a remediation that was merely executed and one whose successful outcome was independently verified and reconciled with the original security finding.