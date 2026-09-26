# Cloud Remediation MVP — Architecture

## 1. Project Overview

Cloud Remediation MVP is an initiative to develop a structured approach to identifying and addressing security risks in cloud infrastructure.

The project began with an AWS-focused security baseline and the broader objective of developing a remediation platform that could help organizations move from identifying cloud security issues to implementing and validating corrective actions.

The initial implementation focuses on establishing secure AWS infrastructure configurations using Terraform.

## 2. Problem Statement

Cloud infrastructure can contain security misconfigurations that expose resources to unnecessary risk.

Identifying a misconfiguration is only the first step. Organizations also need a reliable way to determine what needs to change and ensure that the resulting infrastructure configuration satisfies the intended security requirements.

The initial project establishes a foundation for addressing cloud security configuration issues through infrastructure as code.

## 3. Initial Architecture

The initial implementation uses the following technologies:

- Amazon Web Services (AWS) as the cloud environment.
- Terraform for infrastructure provisioning and configuration.
- Python for supporting automation and future remediation capabilities.
- Git for source control and development history.

The initial workflow is centered on defining and managing an AWS security baseline through Terraform.

```text
Developer
    |
    v
Terraform Configuration
    |
    v
AWS Provider
    |
    v
AWS Infrastructure
    |
    v
Security Configuration
```

## 4. Initial AWS Security Baseline

The initial implementation establishes an AWS S3 security baseline.

Terraform provides a repeatable way to define infrastructure resources and their security-related configuration.

This baseline serves as the starting point for future work involving security findings, resource identification, and remediation automation.

## 5. Architectural Direction

The longer-term direction is to develop a remediation platform that extends beyond infrastructure provisioning.

The intended evolution is to connect cloud security findings with affected resources, determine appropriate corrective actions, and establish a controlled process for implementing and validating remediation.

The initial AWS implementation provides the foundation for this broader objective.

## 6. Future Development

Future development is expected to introduce:

- Cloud security finding ingestion.
- Resource inventory and identification.
- Structured remediation workflows.
- Governance and execution controls.
- Independent verification of resulting configurations.
- Support for additional cloud providers.

These capabilities represent the intended development direction and are not claims about the initial implementation.


## 7. Security Hub Integration and Resource Inventory

The next architectural milestone introduced the ability to retrieve cloud security findings from AWS Security Hub and associate them with discovered AWS infrastructure resources.

This expanded the project beyond managing an initial security baseline toward identifying security issues within an existing cloud environment.

The architecture introduced two important capabilities:

### 7.1 Security Finding Ingestion

A Python-based adapter retrieves findings from AWS Security Hub through the AWS CLI.

This establishes a source of security findings that can be processed by downstream remediation components.

### 7.2 Resource Inventory

A resource inventory component discovers AWS resources and records information that can be used to identify infrastructure affected by security findings.

Initial finding-to-resource matching connects finding metadata with discovered resource information.

This establishes the foundation for resource-aware remediation planning.

### 7.3 Architectural Workflow

```text
AWS Security Hub
       |
       v
Finding Ingestion
       |
       v
Finding Normalization
       |
       v
AWS Resource Inventory
       |
       v
Finding-to-Resource Matching
```

At this stage, the project established the initial integration between security detection and infrastructure identification. Automated remediation proposal generation and controlled execution were subsequent development milestones.


## 8. Synthetic Findings and Remediation Proposal Generation

The next development milestone introduced a structured approach to evaluating remediation workflows using synthetic security findings.

Synthetic findings provided a controlled input for developing and testing remediation logic before relying on live security findings.

### 8.1 Synthetic Finding Fixtures

The architecture introduced synthetic finding data representing cloud security misconfigurations.

These fixtures allowed the project to test how security issues could be processed and associated with potential remediation actions.

### 8.2 Remediation Catalog

A structured remediation catalog established a foundation for defining supported corrective actions and their expected configuration changes.

This separated remediation definitions from the logic responsible for processing findings and generating proposals.

### 8.3 Proposal Generation

The proposal generation component processes eligible findings and produces structured remediation proposals.

Proposals represent proposed corrective actions and provide a basis for subsequent review.

New proposals are maintained in a draft state, with execution disabled by default.

### 8.4 Architectural Workflow

```text
Synthetic Security Finding
          |
          v
Finding Processing
          |
          v
Remediation Catalog
          |
          v
Proposal Generation
          |
          v
Draft Remediation Proposal
```

At this stage, the project established the distinction between identifying a security issue and generating a structured remediation proposal. Governance, authorization, and controlled execution remained subsequent development stages.


## 9. Real Security Hub Finding Remediation Workflow

This milestone extended the proposal-generation architecture to process real security findings retrieved from AWS Security Hub.

The project moved beyond synthetic testing toward generating remediation proposals based on actual cloud security findings and their associated infrastructure resources.

### 9.1 Real Finding Processing

The real finding workflow uses Security Hub finding information to identify security issues and determine the affected AWS resources.

The finding data provides the context needed to evaluate whether a supported remediation action can be proposed.

### 9.2 Resource-Aware Proposal Generation

The proposal-generation workflow uses real finding information and resource context to construct structured remediation proposals.

This establishes a connection between security detection, resource identification, and remediation planning.

### 9.3 Separation of Planning and Execution

Generating a proposal does not modify AWS infrastructure.

The proposal represents a recommended corrective action that can be evaluated through subsequent governance and execution workflows.

### 9.4 Architectural Workflow

```text id="p8q5xk"
AWS Security Hub Finding
          |
          v
Finding Ingestion
          |
          v
Resource Identification
          |
          v
Remediation Evaluation
          |
          v
Real Finding Proposal
          |
          v
Draft Remediation
```

This milestone established the initial real-finding remediation workflow. Governance review and controlled infrastructure execution were developed as subsequent capabilities.


## 10. Remediation Governance and Review Architecture

This milestone introduced governance capabilities for evaluating remediation proposals before infrastructure changes are carried out.

The governance workflow provides a structured way to review proposed actions, record decisions, and preserve the rationale and evidence associated with those decisions.

### 10.1 Proposal Review

Remediation proposals can be evaluated before execution. The review process considers the proposed corrective action and its supporting context.

### 10.2 Review Decisions and Audit History

The governance component records review decisions and associated information, including the proposal being reviewed, the decision, and its rationale.

These records establish an auditable history of remediation review.

### 10.3 Separation of Governance and Execution

Governance review and infrastructure execution are distinct responsibilities.

A governance decision records the outcome of a review. It should not be interpreted as proof that an infrastructure change was executed or that the execution engine independently authorized that change.

Controlled execution and its explicit authorization safeguards were developed in a subsequent milestone.

### 10.4 Architectural Workflow

Remediation Proposal
  → Governance Review
  → Reviewer Decision
  → Decision and Rationale Recorded
  → Auditable Review History

This milestone established the governance and review layer between remediation planning and later controlled execution.


## 11. Expanded Resource Inventory and Finding Matching

This milestone expanded the resource inventory and improved the association between AWS Security Hub findings and discovered infrastructure resources.

The architecture moved beyond the initial inventory implementation to support a broader set of AWS resource types and more structured resource identification.

### 11.1 Expanded Resource Discovery

The inventory component collects information about supported AWS resources and records their identifying attributes.

This inventory provides resource context that can be used when evaluating security findings and preparing remediation proposals.

### 11.2 Resource Type Mapping

Security Hub findings and inventory records may represent resources using different resource-type conventions.

The matching workflow uses resource-type mapping and resource identifiers to associate findings with corresponding inventory entries.

### 11.3 Finding Classification and Matching

The matching process distinguishes between:

- Findings successfully associated with an inventoried resource.
- Resource-related findings that could not be matched.
- Account-level findings that do not identify an individual infrastructure resource.

This distinction prevents account-level findings from being treated as resource-specific remediation targets without sufficient resource context.

### 11.4 Infrastructure Management Context

The inventory work also introduced management context for identifying resources associated with infrastructure-as-code workflows, including Terraform-managed resources where that information is available.

Management metadata supports later remediation planning, but inventory discovery alone does not establish that every resource can be safely or automatically modified.

### 11.5 Architectural Workflow

AWS Security Hub Findings
  → Finding Normalization
  → Resource Type Mapping
  → AWS Resource Inventory
  → Resource Identifier Matching
  → Matched and Unmatched Finding Classification
  → Resource Context for Remediation Planning

This milestone improved the resource-awareness of the platform. Ownership intelligence and broader cloud-agnostic resource discovery remain separate capabilities rather than assumed outcomes of this AWS inventory implementation.


## 12. Controlled Remediation Execution Framework

This milestone introduced the controlled execution architecture for carrying out approved and explicitly authorized remediation actions.

The execution engine provides a structured boundary between remediation planning and infrastructure modification. Its purpose is to ensure that proposed changes are validated and reviewed before they are applied.

### 12.1 Terraform Plan Validation

The execution workflow uses a saved Terraform plan as the basis for evaluating the intended infrastructure change.

Before execution, the platform validates the plan and checks that its proposed resource changes match the expected remediation scope.

### 12.2 Execution Safety Checks

The controlled execution process includes safeguards such as:

- Confirming the expected AWS account and region.
- Validating the target resource and expected Terraform changes.
- Checking saved-plan integrity.
- Reviewing the planned additions, modifications, and deletions.
- Requiring explicit authorization tied to the remediation proposal.

These checks help prevent an execution from applying an unexpected or incorrectly scoped infrastructure change.

### 12.3 Controlled Execution

After validation and explicit authorization, the execution engine applies the saved Terraform plan.

Execution results are recorded as evidence so that subsequent verification and audit workflows can distinguish an attempted change from a successfully completed change.

### 12.4 Separation of Execution and Verification

Successful infrastructure execution does not, by itself, establish that the security issue has been resolved.

Verification is a separate step that evaluates the resulting cloud configuration against the expected security condition.

### 12.5 Architectural Workflow

Remediation Proposal
  → Terraform Plan Generation
  → Saved Plan Validation
  → Account and Resource Confirmation
  → Explicit Execution Authorization
  → Controlled Terraform Apply
  → Execution Evidence

This milestone established the controlled execution layer. Independent verification and reconciliation with Security Hub were developed and strengthened in subsequent milestones.


## 13. S3 TLS Enforcement Remediation Workflow

This milestone demonstrated the controlled remediation workflow against a real AWS Security Hub finding for S3 bucket TLS enforcement (S3.5).

The implementation connected finding-driven proposal generation with Terraform plan validation, explicit execution authorization, controlled infrastructure changes, and direct verification of the resulting bucket policy.

### 13.1 Real Finding and Proposal Generation

The workflow began with a real Security Hub S3.5 finding.

The platform used the finding and its resource context to generate a structured remediation proposal describing the required TLS enforcement action.

### 13.2 Terraform Plan Review

A saved Terraform plan was generated for the proposed remediation.

The plan was reviewed to confirm that it contained exactly one resource creation, with no resource modifications or deletions. This constrained the proposed infrastructure change to the expected remediation scope.

### 13.3 Explicit Authorization and Execution

After plan validation and review, execution required explicit authorization associated with the expected proposal ID.

The remediation was applied through the controlled execution engine using the validated saved Terraform plan.

### 13.4 Independent Configuration Verification

After execution, a direct AWS bucket-policy verification checked whether the bucket policy enforced secure transport.

The verification result was COMPLIANT.

This independent check provided evidence of the resulting security configuration rather than relying only on Terraform reporting successful execution.

### 13.5 Security Hub Reassessment

Direct configuration verification and Security Hub reassessment are separate activities.

The direct verification established the bucket-policy condition. Security Hub subsequently needed to reassess the resource and update its finding status.

### 13.6 Architectural Workflow

Security Hub S3.5 Finding
  → Resource Identification
  → Remediation Proposal
  → Terraform Saved Plan
  → Plan Validation and Review
  → Explicit Proposal-ID Authorization
  → Controlled Execution Engine
  → Direct S3 Bucket Policy Verification
  → Security Hub Reassessment

This milestone demonstrated a successful controlled S3 TLS remediation through the platform execution workflow. It established an end-to-end implementation path from a real finding to independently verified configuration compliance.


## 13. S3 TLS Enforcement Remediation Workflow

This milestone demonstrated the controlled remediation workflow against a real AWS Security Hub finding for S3 bucket TLS enforcement (S3.5).

The implementation connected finding-driven proposal generation with Terraform plan validation, explicit execution authorization, controlled infrastructure changes, and direct verification of the resulting bucket policy.

### 13.1 Real Finding and Proposal Generation

The workflow began with a real Security Hub S3.5 finding.

The platform used the finding and its resource context to generate a structured remediation proposal describing the required TLS enforcement action.

### 13.2 Terraform Plan Review

A saved Terraform plan was generated for the proposed remediation.

The plan was reviewed to confirm that it contained exactly one resource creation, with no resource modifications or deletions. This constrained the proposed infrastructure change to the expected remediation scope.

### 13.3 Explicit Authorization and Execution

After plan validation and review, execution required explicit authorization associated with the expected proposal ID.

The remediation was applied through the controlled execution engine using the validated saved Terraform plan.

### 13.4 Independent Configuration Verification

After execution, a direct AWS bucket-policy verification checked whether the bucket policy enforced secure transport.

The verification result was COMPLIANT.

This independent check provided evidence of the resulting security configuration rather than relying only on Terraform reporting successful execution.

### 13.5 Security Hub Reassessment

Direct configuration verification and Security Hub reassessment are separate activities.

The direct verification established the bucket-policy condition. Security Hub subsequently needed to reassess the resource and update its finding status.

### 13.6 Architectural Workflow

Security Hub S3.5 Finding
  → Resource Identification
  → Remediation Proposal
  → Terraform Saved Plan
  → Plan Validation and Review
  → Explicit Proposal-ID Authorization
  → Controlled Execution Engine
  → Direct S3 Bucket Policy Verification
  → Security Hub Reassessment

This milestone demonstrated a successful controlled S3 TLS remediation through the platform execution workflow. It established an end-to-end implementation path from a real finding to independently verified configuration compliance.
## 14. Remediation Reconciliation and Evidence Validation

This milestone introduced a reconciliation workflow for evaluating whether a remediation proposal has supporting execution and verification evidence and whether the corresponding Security Hub finding reflects the expected security state.

The reconciliation component provides a structured way to connect proposal records, execution events, direct verification results, and Security Hub status.

### 14.1 Evidence Correlation

The reconciliation workflow validates that evidence belongs to the expected remediation operation.

Evidence is correlated using identifying attributes including:

- Proposal ID.
- Finding ID.
- Resource ID.
- AWS account.
- AWS region.

This prevents unrelated execution or verification records from being treated as evidence for the proposal being reconciled.

### 14.2 Execution Evidence Validation

Execution evidence must establish that the expected remediation was successfully applied.

An execution event marked as APPLIED must include a completion timestamp. The reconciliation process evaluates the execution evidence rather than assuming that proposal approval or plan generation means infrastructure was changed.

### 14.3 Verification Evidence Validation

Verification evidence must establish that the expected security configuration was independently checked.

For the S3 TLS workflow, the evidence includes the direct bucket-policy verification result and the corresponding Security Hub control status.

The reconciliation logic checks the expected execution and verification states and requires valid timestamps. Verification must occur at or after the recorded execution completion time.

Timestamps are parsed as timezone-aware values so that malformed or ambiguous timestamps cannot silently satisfy chronology checks.

### 14.4 Security Hub Reconciliation

Direct cloud configuration verification and Security Hub status are evaluated as distinct evidence sources.

The reconciliation workflow checks whether the expected Security Hub control status is available alongside the direct verification evidence. This supports a more complete assessment of whether the remediation is reflected in the security monitoring system.

### 14.5 Controlled Reconciliation and Auditability

The reconciliation process validates evidence before applying a reconciliation decision.

Applying a reconciliation result is an explicit operation rather than an automatic consequence of generating a proposal or collecting evidence. Reconciliation activity is recorded to preserve an auditable history.

### 14.6 Architectural Workflow

Remediation Proposal
  → Execution Evidence
  → Direct Verification Evidence
  → Security Hub Control Status
  → Identity and Chronology Validation
  → Reconciliation Decision
  → Reconciliation Audit Record

This milestone strengthened the platform's ability to establish evidence-backed remediation outcomes and distinguish successful execution from verified and reconciled resolution.

