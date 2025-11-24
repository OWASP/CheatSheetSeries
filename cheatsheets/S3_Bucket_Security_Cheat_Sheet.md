# S3 Bucket Security Cheat Sheet

## 1. Bucket Access Control

### 1.1 Block Public Access (BPA)  

- Enable **all four** Block Public Access settings:  
  -- Block public ACLs  
  -- Block public bucket policies  
  -- Ignore public ACLs  
  -- Restrict public bucket access  
- Principle: **Public buckets should be the exception**, not the default.

### 1.2 Avoid Using ACLs  

- Set bucket ACL to `private`.  
- Use **“Object Ownership: Bucket Owner Enforced”** to disable ACLs.  
- Prefer **IAM policies** instead of ACLs for access control.

### 1.3 Bucket Policy Best Practices  

- Use `"Effect": "Deny"` for deny-by-default conditions.  
- **Require server-side encryption**:

  ```json
  {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::your-bucket-name/*",
    "Condition": {
      "Bool": { "s3:x-amz-server-side-encryption": "false" }
    }
  }
    ```

- **Restrict access to specific VPC endpoints or IP ranges**:

  ```json
  "Condition": {
    "StringNotEquals": { "aws:SourceVpce": "vpce-0123456789abcdef0" }
  }
  ```

- **Force TLS** (deny non-SSL requests):

  ```json
  "Condition": {
    "Bool": { "aws:SecureTransport": "false" }
  }
  ```

## 2. Identity & Access Management (IAM)

### 2.1 Use IAM Roles Instead of Static Users

- Use roles for programs, applications, or compute services — avoid long-lived credentials.

### 2.2 Principle of Least Privilege

- Avoid `"Action": "s3:*"` if not necessary.
- Grant only required actions, e.g.:

  ```json
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ]
  ```

### 2.3 Use VPC Endpoint Policies

- Restrict S3 access to your VPC using a VPC endpoint (Gateway Endpoint).

  ```json
  {
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::your-bucket-name/*",
    "Condition": {
      "StringEquals": { "aws:SourceVpce": "vpce-0123456789abcdef0" }
    }
  }
  ```

## 3. Encryption

### 3.1 Server-Side Encryption (SSE)

- Prefer **SSE-KMS** for strong control and key management.
- Define and use AWS KMS CMKs with restrictive key policies.
- Encrypt data **both at rest and in transit**.

### 3.2 Enforce KMS Usage in Bucket Policy

```json
"Condition": {
  "StringNotEquals": {
    "s3:x-amz-server-side-encryption": "aws:kms"
  }
}
```

### 3.3 Use KMS Bucket Keys

- Enables fewer KMS requests.
- Reduces cost and improves performance for SSE-KMS.

## 4. Logging & Monitoring

### 4.1 Enable Server Access Logging

- Store logs in a **separate, dedicated bucket** (for security and integrity).

### 4.2 Enable CloudTrail Data Events

- Turn on **S3 data event logging** for `GetObject`, `PutObject`, `DeleteObject`.
- This provides visibility on object-level access.

### 4.3 Enable Object-Level Logging

- Use **CloudTrail object-level** logging for sensitive or critical buckets.

### 4.4 Monitor with CloudWatch

Set up CloudWatch Alarms for:

- Creation of public buckets
- Changes to bucket ACLs or policies
- KMS key usage from unrecognized principals
- Access from unexpected IP ranges

## 5. Data Protection & Lifecycle

### 5.1 Versioning

- Enable **versioning** to protect against accidental or malicious deletes.
- Required for replication.

### 5.2 MFA Delete

- Enable **MFA Delete** to require MFA for version deletion or changing versioning state.

### 5.3 Lifecycle Policies

- Archive old versions to **Glacier / S3 Glacier Deep Archive**.
- Expire old versions if not needed.
- Use transitions to optimize costs.

## 6. Network Security

### 6.1 Use VPC Endpoints

- Use **S3 Gateway VPC Endpoint** for private network access.
- Avoid traffic to S3 over the public internet.
- Apply endpoint policies for access restriction.

### 6.2 Avoid Public S3 URLs

- Use pre-signed URLs with limited time validity.
- Alternatively, use **CloudFront + signed URLs** for secure distribution.

## 7. Secure Data Access Patterns

### 7.1 Pre-Signed URLs

- Limit expiration time (e.g., 5–60 minutes).
- Use them for granting temporary, scoped access.

### 7.2 Use S3 Access Points

- Use **VPC-only access points** for more controlled access.
- Define fine-grained routing and permissions per access point.

## 8. Replication & Backup

### 8.1 Use Cross-Region Replication (CRR)

- Enable CRR for disaster recovery / geographic redundancy.

### 8.2 Ensure Replication Encryption

- Both source and destination buckets should enforce SSE-KMS.

## 9. Misconfiguration Audit Checklist

- [ ] Block Public Access is enabled?
- [ ] Any bucket-wide public access via policy / ACL?
- [ ] ACLs are disabled (`Object Ownership = Bucket Owner Enforced`)?
- [ ] Bucket policies restrict to VPC / trusted sources?
- [ ] Encryption is enforced (SSE-KMS)?
- [ ] Versioning is enabled?
- [ ] MFA Delete is enabled (if needed)?
- [ ] CloudTrail Data Events for S3 turned on?
- [ ] Separate logging bucket established?
- [ ] VPC Endpoint used for S3 access?
- [ ] Pre-signed URLs expiring quickly / CloudFront used for distribution?

## 10. Additional Tips

- Regularly **review your bucket policies and IAM roles**.
- Use **AWS Config** to check for non-compliant buckets (public access, encryption, versioning).
- Use **AWS Trusted Advisor** / **S3 Storage Lens** to identify risk areas.
- Enable **S3 Object Lock** if you need immutability / write-once-read-many (WORM) behavior.

## References

- [AWS Security Documentation – Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS S3 Presigned URL Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html)
- [AWS Access Analyzer for S3](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [NIST SP 800-53 – Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
