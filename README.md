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