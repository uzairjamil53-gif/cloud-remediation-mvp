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
