# Leaked IAM access key abuse: from repository leak to crypto-mining and S3 theft

> Synthetic report written for RuleSmith's offline demo and evaluation set. It mirrors widely published public reporting on AWS credential compromise; account ids, names and IPs are fictional.

## Summary

A long-term IAM access key belonging to a CI service user was committed to a public GitHub repository in a `.env` file. Within 11 minutes of the push an automated actor validated the key, enumerated the account, created a backdoor user with administrator rights, disabled CloudTrail logging in one region, launched GPU instances for cryptomining in two unused regions, and bulk-downloaded objects from a customer-data bucket.

## Validation and enumeration

The first calls came from a Tor exit node (185.220.101.34) with the user agent `aws-cli/1.33.12 Python/3.11.2 Linux/6.1.0-kali` and were made by the leaked identity `arn:aws:iam::123456789012:user/ci-deployer`:

```
sts:GetCallerIdentity
iam:ListUsers
iam:ListAttachedUserPolicies
iam:GetAccountAuthorizationDetails
s3:ListBuckets
ec2:DescribeInstances (every region)
```

`GetAccountAuthorizationDetails` had never been called in the account's history, and `ci-deployer` had only ever been used from the CI provider's IP ranges with the user agent `aws-sdk-go-v2/1.26.0`.

## Persistence: backdoor user and key

The actor created a new user and gave it full administrative rights:

```
iam:CreateUser            userName=backup-svc
iam:CreateAccessKey       userName=backup-svc
iam:AttachUserPolicy      userName=backup-svc policyArn=arn:aws:iam::aws:policy/AdministratorAccess
iam:CreateLoginProfile    userName=backup-svc (console password set)
```

All subsequent activity used `backup-svc`. In a second victim account the actor instead called `iam:UpdateAccessKey` to reactivate a disabled key of an existing user and `iam:AttachRolePolicy` to add `AdministratorAccess` to a role it could assume.

## Defence evasion

In `us-east-1` the actor stopped and later deleted the organisation trail:

```
cloudtrail:StopLogging    name=org-trail
cloudtrail:DeleteTrail    name=org-trail
```

It also called `guardduty:DeleteDetector` in the same region. Both calls were made by `backup-svc` from the Tor exit node. No legitimate principal in the account had ever called `StopLogging` or `DeleteDetector`.

## Resource hijacking

Within an hour the actor launched sixteen `p4d.24xlarge` instances in `ap-south-1` and `sa-east-1`, regions the organisation had never used, each with user data that installed XMRig:

```
ec2:RunInstances   instanceType=p4d.24xlarge count=8 (ap-south-1)
ec2:RunInstances   instanceType=p4d.24xlarge count=8 (sa-east-1)
```

The call preceded `ec2:CreateKeyPair` and `ec2:AuthorizeSecurityGroupIngress` with `0.0.0.0/0` on port 22. Service quotas limited the actual launch to four instances per region.

## Collection and exfiltration

The actor listed and downloaded objects from the bucket `acme-customer-exports` using `s3:ListObjectsV2` followed by thousands of `s3:GetObject` calls over 40 minutes, 23 GB in total, all from the Tor exit node. The bucket had previously only been read by the `DataPipelineRole` role from inside the VPC. The actor also called `s3:PutBucketPolicy` on the bucket to grant `Principal: "*"` read access, which was caught by the organisation's SCP and returned `AccessDenied`.

## Indicators

| Type | Value |
|---|---|
| IP | 185.220.101.34 (Tor exit) |
| User agent | aws-cli/1.33.12 Python/3.11.2 Linux/6.1.0-kali |
| IAM user created | backup-svc |
| Regions abused | ap-south-1, sa-east-1 |

## Recommendations

Alert on `GetAccountAuthorizationDetails`, on `CreateUser` followed by `CreateAccessKey` and `AttachUserPolicy` with `AdministratorAccess`, on `StopLogging`, `DeleteTrail` and `DeleteDetector`, on `RunInstances` for accelerated-compute instance types in never-used regions, on `PutBucketPolicy` granting public principals, and on high-volume `GetObject` from a principal that has never read the bucket before. Rotate the CI key, enable IAM Access Analyzer, and require short-lived credentials for CI.
