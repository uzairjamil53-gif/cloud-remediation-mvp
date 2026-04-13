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
