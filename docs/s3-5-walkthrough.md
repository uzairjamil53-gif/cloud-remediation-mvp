# S3.5 Remediation Walkthrough — Enforcing TLS for Amazon S3

## 1. Overview

This walkthrough documents an end-to-end AWS S3 security remediation performed using the Cloud Remediation MVP.

The demonstration addresses AWS Security Hub control **S3.5 — S3 general purpose buckets should require requests to use TLS**.

The objective was to demonstrate how a security finding can be transformed into a controlled, governed, executable, independently verifiable, and reconciled remediation.

Unlike a conventional workflow that stops after identifying a security finding, the MVP connects detection, resource identification, remediation proposal generation, execution authorization, Terraform-based execution, independent verification, and Security Hub reassessment.

## 2. Security Finding

AWS Security Hub identified an S3.5 security control failure affecting an Amazon S3 general purpose bucket.

The finding indicated that the bucket did not enforce encrypted transport through TLS.

The relevant security requirements are:

- Requests to the S3 bucket must use HTTPS/TLS.
- Requests using unencrypted transport must be denied.
- The remediation must not unnecessarily disrupt existing bucket functionality.

The MVP retrieved the finding through its AWS Security Hub integration and used the finding details to identify the affected resource and remediation context.

For public documentation, account identifiers, resource ARNs, and other environment-specific identifiers are intentionally omitted.

## 3. Finding Normalization and Resource Identification

The remediation workflow begins by processing the Security Hub finding.

The platform extracts relevant information, including:

- Cloud provider.
- AWS account context.
- AWS region.
- Security control identifier.
- Finding identifier.
- Affected resource type.
- Affected resource identifier.
- Finding severity and compliance status.

The finding is correlated with the resource inventory to establish the target resource for remediation.

This step is important because a security finding must be associated with an identifiable resource before a remediation action can be proposed.

The MVP uses resource identification and matching rather than assuming that every finding directly provides all the information needed for execution.

## 4. Initial Configuration Assessment

Before generating an executable remediation proposal, the affected bucket's live configuration was inspected.

The assessment used the AWS S3 API to retrieve the bucket policy.

The initial assessment established that:

- A bucket policy was not present.
- TLS enforcement was not configured.
- The bucket was therefore non-compliant with the intended S3.5 requirement.

The initial verification result was recorded as **NON_COMPLIANT**.

This assessment provided configuration evidence for the remediation decision rather than relying exclusively on the Security Hub finding.

## 5. Remediation Proposal Generation

After identifying the affected resource and confirming its configuration, the MVP generated a remediation proposal.

The proposal included:

- The associated Security Hub finding.
- The affected S3 resource.
- The target AWS account and region context.
- The remediation objective.
- The expected configuration change.
- The supporting configuration evidence.
- Execution and verification requirements.

The proposed remediation was to introduce an S3 bucket policy that explicitly denies requests that do not use TLS.

The proposal was maintained as a distinct artifact so that identifying a security issue did not automatically authorize infrastructure changes.

## 6. Governance and Execution Authorization

The MVP separates remediation proposal generation from execution.

Before applying the remediation, the workflow required explicit interactive confirmation of the exact proposal identifier.

The execution process also performed safety checks associated with the approved proposal and its Terraform plan.

The intent of these controls is to prevent a finding from automatically triggering an infrastructure modification without an identifiable proposal and an explicit execution decision.

The execution process was designed to validate the proposed action before applying it.

## 7. Terraform Plan Review

The remediation was represented through Terraform.

Before execution, the saved Terraform plan was reviewed and validated.

The reviewed plan contained:

- One resource creation.
- No existing resource modifications.
- No resource deletions.

This was an important safety condition because the remediation was intended to introduce the required TLS enforcement policy without unnecessarily changing or removing existing infrastructure.

The execution workflow used the reviewed saved plan rather than generating an unrelated plan at application time.

The MVP also incorporated plan-integrity and resource-validation checks into its controlled execution process.

## 8. Controlled Remediation Execution

After the proposal authorization and Terraform plan checks, the remediation was executed through the MVP's execution engine.

The execution process used the Terraform saved-plan workflow.

The execution audit recorded:

- The remediation proposal identifier.
- The associated finding and resource.
- The AWS account and region context.
- The saved plan hash.
- The execution authorization method.
- The execution method.
- The execution status.

The Terraform application completed successfully and recorded the execution status as **APPLIED**.

Importantly, the platform did not treat successful Terraform application alone as proof that the security issue had been resolved.

Independent verification was still required.

## 9. Independent Verification

Following execution, the MVP inspected the live S3 bucket configuration again.

The first verification attempt returned **FAILED** because the expected TLS protection was not detected.

The workflow did not treat this initial failed verification as successful remediation.

A subsequent direct inspection of the bucket policy confirmed that the expected TLS enforcement was present.

The successful verification recorded:

- Execution status: APPLIED.
- Direct verification status: COMPLIANT.
- Verification method: direct S3 bucket policy check.

This demonstrated the distinction between infrastructure execution and independent confirmation of the resulting security configuration.

The final verification result was **COMPLIANT**.

## 10. Security Hub Reassessment

After the direct configuration verification, the AWS Security Hub control was reassessed.

The recorded reassessment evidence showed:

- Security Hub control: S3.5.
- Compliance status: PASSED.
- Workflow status: RESOLVED.

This provided an additional confirmation from the original security detection platform.

The workflow therefore relied on both direct AWS configuration verification and Security Hub reassessment rather than assuming that a successful Terraform apply automatically resolved the finding.

## 11. Proposal Reconciliation and Audit Evidence

The final stage connected the proposal, execution, verification, and Security Hub evidence.

The reconciliation process correlated the relevant evidence using:

- Proposal identifier.
- Finding identifier.
- Resource identifier.
- AWS account.
- AWS region.

The reconciliation record reflected the following final state:

| Evidence element | Recorded result |
|---|---|
| Proposal status | VERIFIED |
| Execution status | APPLIED |
| Direct verification | COMPLIANT |
| Security Hub compliance | PASSED |
| Security Hub workflow | RESOLVED |
| Further execution permitted | No |

The reconciliation stage established that the remediation had progressed beyond proposal generation and execution into independent verification and security finding resolution.

The execution and verification audit records also retained the initial failed verification event, followed by the successful verification event.

This preserves the distinction between an unsuccessful verification attempt and the later confirmed compliant configuration.

## 12. Security and Execution Safeguards

The S3.5 demonstration illustrates several important safeguards incorporated into the MVP:

1. **Finding-driven remediation:** Remediation begins with an identified security finding.
2. **Resource identification:** The affected resource is identified before a remediation action is proposed.
3. **Evidence-based decisions:** Live configuration is inspected before remediation.
4. **Proposal separation:** Generating a proposal does not automatically execute it.
5. **Explicit authorization:** Execution requires interactive confirmation of the proposal identifier.
6. **Terraform plan validation:** The saved plan is reviewed and checked before application.
7. **Controlled execution:** The execution engine applies the validated saved plan.
8. **Independent verification:** The resulting AWS configuration is inspected directly.
9. **Security Hub reassessment:** The original security control is checked again.
10. **Evidence reconciliation:** Execution, verification, and finding resolution are correlated.

These safeguards demonstrate the project's focus on risk-governed remediation rather than unreviewed automatic infrastructure changes.

## 13. Demonstrated Capabilities and Current Scope

This demonstration establishes that the MVP can connect several stages of the cloud security remediation lifecycle:

- Security Hub finding ingestion.
- Finding normalization and resource identification.
- Live configuration assessment.
- Remediation proposal generation.
- Explicit execution authorization.
- Terraform plan validation.
- Controlled infrastructure execution.
- Independent AWS configuration verification.
- Security Hub reassessment.
- Proposal reconciliation and audit evidence validation.

The demonstration represents an AWS implementation of the broader cloud remediation control-plane concept.

The current MVP should not be interpreted as a fully production-ready multi-cloud remediation platform. Its demonstrated live execution workflow is AWS-focused, and additional integrations, cloud-specific execution adapters, operational controls, and broader testing would be required to extend the implementation across AWS, Azure, and GCP.

## 14. Conclusion

The S3.5 demonstration shows how the Cloud Remediation MVP moves beyond identifying a cloud security finding and connects it to a controlled remediation lifecycle.

The project successfully demonstrated a real AWS remediation in which a missing TLS enforcement configuration was identified, assessed, proposed, authorized, applied through a reviewed Terraform plan, independently verified, reassessed by Security Hub, and reconciled through recorded evidence.

The demonstration supports the central engineering objective of the project: developing risk-governed, closed-loop cloud security remediation approaches that improve the ability of organizations to identify, prioritize, remediate, and continuously validate cybersecurity risks across cloud infrastructure.
