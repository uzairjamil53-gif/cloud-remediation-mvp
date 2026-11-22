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

## EC2 Default Security Group Remediation Proposals

This milestone expanded the remediation platform to address AWS EC2 default security group misconfigurations.

The objective was to extend the proposal-generation framework beyond S3 and demonstrate how the platform could handle remediation requirements for additional AWS resource types.

The implementation introduced:

- A dedicated EC2 default security group proposal generator.
- Identification and processing of relevant Security Hub EC2.2 findings.
- Evaluation of default security group configuration and remediation prerequisites.
- Structured remediation proposals for closing unrestricted default security group access.
- Resource-specific verification capabilities.
- Unit tests covering EC2 default security group proposal generation.

This milestone demonstrated the extensibility of the remediation framework across different AWS resource types. The EC2.2 workflow established proposal-generation and verification capabilities; proposal generation did not itself constitute an executed remediation.

## Phase 9 Completion: Execution Hardening and Remediation Verification

This milestone focused on final hardening and acceptance review of the controlled remediation framework.

The work expanded remediation coverage, strengthened execution safeguards, and improved the reliability of evidence used to validate remediation outcomes.

The implementation and validation included:

- Hardening of remediation execution and reconciliation workflows.
- Improved validation of execution and verification evidence, including event chronology and resource identity correlation.
- Additional S3 remediation capabilities, including lifecycle configuration and server access logging.
- Discovery of existing S3 logging destinations to support remediation planning.
- Direct AWS configuration verification following remediation execution.
- Security Hub status reconciliation to evaluate whether the original security finding reflected the remediated configuration.
- Expanded automated test coverage across inventory, proposal generation, governance, execution, verification, and reconciliation.

The project demonstrated controlled AWS remediation through reviewed Terraform plans, explicit execution authorization, direct configuration verification, and evidence-based reconciliation.

At this stage, the platform had established a working AWS remediation foundation, while broader multi-cloud execution and additional remediation integrations remained future development objectives.

## Architecture

The platform is organized into distinct components that support the remediation lifecycle.

### Remediation Lifecycle

1. **Detection:** Retrieve security findings from AWS Security Hub.
2. **Finding Normalization:** Normalize finding metadata and affected resource information.
3. **Resource Identification:** Discover AWS resources and correlate findings with inventory records.
4. **Management Context:** Identify available infrastructure management information, including Terraform-managed resources.
5. **Remediation Planning:** Evaluate findings against remediation catalogs and generate structured proposals.
6. **Governance:** Record review decisions and determine whether a proposal is authorized for execution.
7. **Controlled Execution:** Validate and execute approved Terraform remediation plans through the execution engine.
8. **Independent Verification:** Inspect the resulting AWS configuration to determine whether the intended security requirement has been satisfied.
9. **Reconciliation:** Validate execution and verification evidence and reconcile the outcome with AWS Security Hub.

### Core Components

| Component | Responsibility |
|---|---|
| Security Hub Adapter | Retrieves and normalizes AWS Security Hub findings |
| Resource Inventory | Discovers AWS resources and their configuration context |
| Finding Matcher | Associates security findings with discovered resources |
| Remediation Catalog | Defines supported remediation actions and requirements |
| Proposal Generator | Produces structured remediation proposals |
| Governance Engine | Records review decisions and execution authorization |
| Execution Engine | Validates and executes authorized Terraform plans |
| Verification Modules | Independently inspect AWS configurations |
| Reconciliation Engine | Validates evidence and reconciles remediation outcomes |

## Repository Structure

The repository is organized by functional responsibility.

```text
cloud-remediation-mvp/
├── aws-s3-baseline/
│   ├── main.tf
│   └── .terraform.lock.hcl
├── findings/
│   ├── fixtures/
│   ├── securityhub_adapter.py
│   └── match_inventory.py
├── inventory/
│   └── inventory.py
├── remediation/
│   ├── catalog/
│   ├── proposals/
│   ├── audit/
│   ├── proposal_generator.py
│   ├── real_finding_proposal_generator.py
│   ├── real_s3_tls_proposal_generator.py
│   ├── ec2_default_security_group_proposal_generator.py
│   ├── governance.py
│   ├── execution_engine.py
│   ├── reconcile_proposal.py
│   ├── discover_s3_logging_destinations.py
│   └── verify_*.py
├── tests/
├── .gitignore
├── LICENSE
└── README.md
```

Runtime-generated proposals, findings, verification results, and audit records are maintained separately from the core implementation.

## Prerequisites

The current AWS implementation uses:

- Python 3
- Terraform 1.6 or later
- AWS CLI
- An AWS account with the required permissions
- AWS Security Hub CSPM enabled
- Git

Terraform providers used by the baseline configuration:

- HashiCorp AWS provider, version 6.x
- HashiCorp Random provider, version 3.6 or later

Python dependencies are currently based on the Python standard library and external command-line integrations rather than a packaged dependency manifest.

## Setup

Clone the repository:

```bash
git clone https://github.com/uzairjamil53-gif/cloud-remediation-mvp.git
cd cloud-remediation-mvp
```

Verify the installed tools:

```bash
python --version
terraform version
aws --version
git --version
```

Configure AWS CLI credentials using your preferred AWS authentication method.

Verify the active AWS identity:

```bash
aws sts get-caller-identity
```

Initialize and validate the Terraform baseline:

```bash
cd aws-s3-baseline

terraform init
terraform validate
```

These commands initialize Terraform providers and validate the configuration. They do not apply infrastructure changes.

Before using Terraform against an AWS account, review the account restrictions and resource configuration in the Terraform files.

## Testing

The project uses Python's built-in `unittest` framework.

Run the complete test suite from the repository root:

```bash
python -m unittest discover -s tests
```

The Phase 9 acceptance review completed with **138 passing tests**.

Test coverage includes:

- Resource inventory and discovery.
- Security finding normalization and matching.
- Synthetic and real finding proposal generation.
- Remediation governance.
- Terraform plan and state validation.
- Controlled execution safeguards.
- S3 configuration verification.
- S3 server access logging discovery and verification.
- EC2 default security group proposal generation.
- Remediation reconciliation and evidence validation.

The tests exercise both successful workflows and failure conditions, including invalid authorization, unexpected Terraform plans, incomplete evidence, and invalid execution or verification chronology.

## Implemented Capabilities

The current implementation establishes an AWS-focused remediation foundation with the following capabilities:

- AWS Security Hub finding retrieval.
- AWS resource inventory and finding correlation.
- Terraform management context identification.
- Catalog-driven remediation proposal generation.
- Governance and review decision tracking.
- Controlled Terraform plan validation and execution.
- Direct AWS configuration verification.
- Execution and verification audit evidence.
- Evidence-based remediation reconciliation.
- S3 security remediation workflows.
- EC2 default security group remediation proposal generation.

### Demonstrated Remediation Workflows

The project has demonstrated controlled AWS remediation through:

- **S3 TLS enforcement:** A reviewed Terraform plan was executed through the remediation engine, followed by direct bucket policy verification.
- **S3 lifecycle configuration:** Incomplete multipart upload cleanup was configured with a seven-day threshold and independently verified.
- **S3 server access logging:** Logging destination discovery, configuration, and verification capabilities were developed.
- **EC2 default security group:** A proposal-generation and verification workflow was developed for Security Hub EC2.2 findings. Proposal generation does not constitute an executed remediation.

## Execution Safety and Governance

The platform is designed to separate remediation planning from execution.

Important safeguards include:

- Remediation proposals are generated in draft status.
- Governance decisions are recorded separately from proposal generation.
- Execution requires explicit authorization.
- Terraform plans are inspected before application.
- Expected resource changes are validated.
- Saved plan integrity is checked before execution.
- Execution and verification evidence are correlated with the original proposal and affected resource.
- Reconciliation validates event chronology and evidence completeness.

The execution engine is not intended to apply arbitrary changes automatically. Remediation must follow the defined validation and authorization workflow.

## Current Scope and Limitations

The current implementation is an AWS-focused MVP.

The following should be considered future development objectives rather than existing capabilities:

- Production-ready Azure and Google Cloud remediation adapters.
- Generalized multi-cloud execution orchestration.
- Broader ownership intelligence and CMDB integrations.
- Expanded infrastructure-as-code management discovery.
- Additional cloud resource remediation catalogs.
- Production-scale deployment and operational integrations.
- Broader closed-loop remediation across multiple cloud providers.

The architecture is intended to support these future extensions, but the current implementation should not be interpreted as a completed multi-cloud remediation platform.

## Future Direction

The long-term direction is to advance a cloud-agnostic remediation control plane that can operate across AWS, Azure, and Google Cloud environments.

The objective is to bridge the gap between identifying security risks and establishing that those risks have been properly remediated.

Future development will focus on expanding cloud provider integrations, improving resource ownership and management intelligence, extending governance capabilities, and strengthening independent verification and reconciliation.

## Project Objective

This project explores the development of risk-governed, closed-loop cloud security remediation approaches that improve how organizations identify, prioritize, remediate, and continuously validate cybersecurity risks across cloud infrastructure.

The MVP provides an initial technical foundation for this objective through its AWS resource inventory, finding correlation, remediation planning, governance, controlled execution, and evidence-based verification capabilities.

## License

Copyright 2026 Uzair Jamil

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the complete license terms.