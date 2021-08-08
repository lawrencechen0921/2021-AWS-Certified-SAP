# AWS Certified Solutions Architect Professional 佛心大補帖
*一個人先給我一股伊雲谷股票(6689)><*[^一股] 
[^一股]:一股會不會太少

2021 7/14 Test Got Certification
## 考題配分占比
![](https://i.imgur.com/gGhpx76.png)

## Preparation Focus Target
**AWS Solutions Architect Professional Preparation~**

1. Identity & Federation(review 2)(8/5 AD很容易忘記)
2. Security(review2)(review 3)
3. Compute & Load Balancing(review 2)(again)
4. Storage(review 2)(review3)
5. Caching(review2)(review3)
6. Databases(review2)(review3)
7. Service Communication（review2)
8. Data Engineering(8/5)
9. Monitoring(8/5)
10. Deployment and Instance Management(review 2)
11. Cost Control(review 2)
12. Migration(review 2)(8/7 Again)
13. VPC(Reviewed 2)(again)
14. Other Services(8/5)
15. Reviews all for 2 times
16. Exam Preparation(8/10考試)

Exam Tips:


**One of the key tactic I followed when solving any question was to read the question and use paper and pencil to draw a rough architecture and focus on the areas that you need to improve**.

Trust me, you will be able eliminate 2 answers for sure and then need to focus on only the other two. Read the other 2 answers to check the difference area and that would help you reach to the right answer or atleast have a 50% chance of getting it right.

Focus on Scalability, HA, Disaster Recovery, Migration, Security, Cost Control

Whitepapers are key to understand

1. Security Processes
2. Disaster Recovery (pilot light, warm standby, RTO and RPO)
3. Cloud Migration(rehost, replatform, rearchitect)

## **Migration & Transfer**

1. Know Cloud Migration Serivce
2. Know Database Migration Service ( Elasticsearch is supported by DMS)

## **Management & Governance Tools**

**AWS Organization Tools**

1. Service Control Policies v.s IAM Policies
2. Systems Manager (understand systems manager and its various service like parameter store, patch manager)
3. Cloudwatch (Cloudwatch logs and Cloudwatch Subscription Filter)
4. Cloudwatch Events
5. Understand CloudTrail audit and governance
6. Cloudformation in terms of Disaster Recovery to replicate environment across regions

## **Networking & Content Delivery**

1. VPC NACL Security Groups
2. Route 53 policies
3. Cloudfront caching
4. API Gateway
5. Private Link
6. ALB ELB
7. ELB + Auto Scaling

## **Security & Identity & Compliance**

1. IAM, WAF Shield DDOS

## **Storage**

1. This exam does not cover storage in deep
2. S3 support (retrieval and partial content using Range Get requests)
3. S3 data protection
4. S3 subresources
5. S3 disaster recovery ( cross region )
6. EBS snapshots for backup and HA
7. Storage Gateway for file based volumes and tape

## **Database**

1. RDS Multi-AZ vs Read Replicas (cross region and availability of data)
2. Aurora DR & HA using Read replicas and Global Database
3. DynamoDB (DynamoDB Streams for tracking changes, DynamoDB Auto Scaling & DAX for caching) improvement of selection of keys.

## **Compute**

1. EC2 instance Type, Auto Scaling
2. Elastic Beanstalk mainly from the perspective of migration
3. VPC & Lambda@Edge
4. Not cover ECS and EKS

## **Analytics**

1. Understand Kinesis
2. Different Between Kinesis Data Strems and Kinesis Firehose
3. Know Elasticsearch provides a manages solution

## Integration Tools

1. SQS Standard and FIFO
2. Cloudwatch integrate with SNS and Lambda can help in notification




---
## Show On
## Identity & Federation

### IAM
- Users: long term credentials
- Groups
- Roles: short-term credentials, uses STS
  - EC2 Instance Roles: uses the EC2 metadata service. One role at a time per instance • ServiceRoles:APIGateway,CodeDeploy,etc...
  - Cross Account roles
- Policies 
  - AWS Managed
  - Customer Managed • Inline Policies
- Resource Based Policies (S3 bucket, SQS queue, etc...)

### IAM Policies Deep Dive
 - Anatomy of a policy: JSON doc with Effect, Action, Resource, Conditions, Policy Variables
- Explicit DENY has precedence over ALLOW
- Best practice: use least privilege for maximum security
  - Access Advisor: See permissions granted and when last accessed
  - AccessAnalyzer:Analyzeresourcesthatare shared with external entity
 - Navigate Examples at: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html
 ![](https://i.imgur.com/SGlSn0T.png)

### IAM AWS Managed Policies
**AdministratorAccess**
```json
{
    "Version":"2012-10-17",
    "Statement":[
        {
            "Effect":"Allow",
            "Action"::"*",
            "Resource":"*"
        }
    ]
}
```
### IAM AWS Managed Policies
**PowerUserAccess**

![](https://i.imgur.com/PvRwBV5.png)

**Note how "NotAction" is used instead of Deny**.

### IAM Policies Variables and Tags
- Example: ${aws:username}
  - "Resource":["arn:aws:s3:::mybucket/${aws:username}/*"]
- AWS Specific:
  - aws:CurrentTime, aws:TokenIssueTime, aws:principaltype, aws:SecureTransport, aws:SourceIp, aws:userid, ec2:SourceInstanceARN
- Service Specific:
  - s3:prefix, s3:max-keys, s3:x-amz-acl, sns:Endpoint, sns:Protocol...
- Tag Based:
  - iam:ResourceTag/key-name, aws:PrincipalTag/key-name...

### IAM Roles vs Resource Based Policies

- Attach a policy to a resource (example: S3 bucket policy) versus attaching of a using a role as a proxy

![](https://i.imgur.com/u5G7hX7.png)

### IAM Roles vs Resource Based Policies
 - When you assume a role (user, application or service), you give up your original permissions and take the permissions assigned to the role
 - When using a resource based policy, the principal doesn’t have to give up any permissions
 - Example: User in account A needs to scan a DynamoDB table in Account A and dump it in an S3 bucket in Account B.
 - Supported by: Amazon S3 buckets, SNS topics, SQS queues

## STS
### Using STS to Assume a Role
- Define an IAM Role within your account or cross-account
- Define which principals can access this IAM Role
- Use AWS STS (Security Token Service) to retrieve credentials and impersonate the IAM Role you have access to (AssumeRole API)
- Temporary credentials can be valid between 15 minutes to 1 hour!

![](https://i.imgur.com/9gBoYmy.png)

### Assuming a Role with STS
- Provide access for an IAM user in one AWS account that you own to access resources in another account that you own
- Provide access to IAM users in AWS accounts owned by third parties
- Provide access for services offered by AWS to AWS resources
- Provide access for externally authenticated users (identity federation)
- Ability to revoke active sessions and credentials for a role(by adding a policy using a time statement – AWSRevokeOlderSessions)
- When you assume a role (user, application or service), you give up your original permissions and take the permissions assigned to the role

### Providing Access to an IAM User in Your or Another AWS Account That You Own
- You can grant your IAM users permission to switch to roles within your AWS account or to roles defined in other AWS accounts that you own.
![](https://i.imgur.com/4HzH6CR.png)

- Benefits:
  - You must explicitly grant your users permission to assume the role.
  - Your users must actively switch to the role using the AWS Management Console or assume the role using the AWS CLI or AWS API
  - You can add multi-factor authentication (MFA) protection to the role so that only users who sign in with an MFA device can assume the role
  - Least privilege + auditing using CloudTrail
### Cross account access with STS
![](https://i.imgur.com/VpVz8wM.png)

### Providing Access to AWS Accounts Owned by Third Parties
- Zone of trust = accounts, organizations that you own
- Outside Zone of Trust = 3rd parties
- Use IAM Access Analyzer to find out which resources are exposed
- For granting access to a 3rd party:
  - The 3rd party AWS account ID
  - An External ID (secret between you and the 3rd party)
     - To uniquely associate with the role between you and 3rd party
    - Must be provided when defining the trust and when assuming the role 
    - Must be chosen by the 3rd party
  - Define permissions in the IAM policy
### The confused deputy
![](https://i.imgur.com/Ox3HpTb.jpg)

### STS Important APIs
- AssumeRole: access a role within your account or cross-account
- AssumeRoleWithSAML: return credentials for users logged with SAML
- AssumeRoleWithWebIdentity: return creds for users logged with an IdP 
  - Example providers include Amazon Cognito, Login with Amazon, Facebook,Google, or any OpenID Connect-compatible identity provider
  - AWS recommends using Cognito instead
- GetSessionToken: for MFA, from a user or AWS account root user
- GetFederationToken: obtain temporary creds for a federated user, usually a proxy app that will give the creds to a distributed app inside a corporate network

### Identity Federation & Cognito
- Federation lets users outside of AWS to assume temporary role for accessing AWS resources.
- These users assume identity provided access role.
- Federations can have many flavors: 
  - SAML 2.0
  - Custom Identity Broker
  - Web Identity Federation with Amazon Cognito
  - Web Identity Federation without Amazon Cognito 
  - Single Sign On
  - Non-SAML with AWS Microsoft AD
- Using federation, you don’t need to create IAM users (user management is outside of AWS)

### SAML 2.0 Federation
- To integrate Active Directory / ADFS with AWS (or any SAML 2.0)
- Provides access to AWS Console or CLI (through temporary creds)
- No need to create an IAM user for each of your employees
![](https://i.imgur.com/4815x6v.png)

### SAML 2.0 Federation – Active Directory FS
- Same process as with any SAML 2.0 compatible IdP
![](https://i.imgur.com/2WXNAtb.png)

### SAML 2.0 Federation
- Needs to setup a trust between AWS IAM and SAML (both ways)
- SAML 2.0 enables web-based, cross domain SSO
- Uses the STS API: AssumeRoleWithSAML
- Note federation through SAML is the “old way” of doing things
- Amazon Single Sign On (SSO) Federation is the new managed and simpler way
- Read more here: https://aws.amazon.com/blogs/security/enabling-federation-to-aws-using-windows-active-directory-adfs-and-saml-2-0/

### Custom Identity Broker Application
- Use only if identity provider is not compatible with SAML 2.0
- The identity broker must determine the appropriate IAM policy
- Uses the STS API: AssumeRole or GetFederationToken
![](https://i.imgur.com/iLRcnwM.png)

### Web Identity Federation – AssumeRoleWithWebIdentity
- Not recommended by AWS – use Cognito instead (allows for anonymous users, data synchronization, MFA)

![](https://i.imgur.com/sbGdIAK.png)

### Web Identity Federation – AWS Cognito
- Preferred way for Web Identity Federation
  - Create IAM Roles using Cognito with the least privilege needed
  - Build trust between the OIDC IdP and AWS
- Cognito benefits:
  - Support for anonymous users
  - Support for MFA
  - Data synchronization
- Cognito replaces a Token Vending Machine (TVM)
![](https://i.imgur.com/3ia7XnM.png)

### Web Identity Federation – IAM Policy
- After being authenticated with Web Identity Federation, you can identify the user with an IAM policy variable.
- Examples:
  - cognito-identity.amazonaws.com:sub
  - www.amazon.com:user_id
  - graph.facebook.com:id
  - accounts.google.com:sub

### What is Microsoft Active Directory (AD)?
- Found on any Windows Server with AD Domain Services
- Database of objects: User Accounts, Computers, Printers, File Shares, Security Groups
- Centralized security management, create account, assign permissions
- Objects are organized in trees
- A group of trees is a forest

![](https://i.imgur.com/bavdKte.png)


### What is ADFS (AD Federation Services)?
- ADFS: provide single sign-on across applications
- SAML across 3rd party:AWS Console,Dropbox,Office365,etc...

![](https://i.imgur.com/YeUqSki.png)

### AWS Directory Services
- AWS Managed Microsoft AD
  - Create your own AD in AWS, manage users locally, supports MFA
  - Establish “trust” connections with your on- premise AD
  
  ![](https://i.imgur.com/2mbNUUv.png)

  
- AD Connector
  - Directory Gateway(proxy) to redirect to on-premise AD
  - Users are managed on the on-premise AD

![](https://i.imgur.com/PI7FGqV.png)

- Simple AD
  - AD-compatible managed directory on AWS
  - Cannot be joined with on-premise AD
![](https://i.imgur.com/xbUARAk.png)

### AWS Directory Services AWS Managed Microsoft AD
- Managed Service:Microsoft AD in yourAWS VPC
- EC2 Windows Instances:
  - EC2 Windows instances can join the domain and run traditional AD applications (sharepoint, etc)
  - Seamlessly Domain Join Amazon EC2 Instances from Multiple Accounts & VPCs
- Integrations:
  - RDS for SQL Server,AWS Workspaces,Quicksight... • AWS SSO to provide access to 3rd party applications
  - Standalone repository in AWS or joined to on- premise AD
  - Multi AZ deployment of AD in 2 AZ, # of DC (Domain Controllers) can be increased for scaling
  - Automated backups

![](https://i.imgur.com/bqrmdev.png)

### Connect to on-premise AD
- Ability to connect your on-premise Active Directory to AWS Managed Microsoft AD
- Must establish a Direct Connect (DX) or VPN connection
- Can setup three kinds of forest trust:
   - One-way trust:AWS => On-Premise
   - One-way trust: On-Premise => AWS
   - Two-way forest trust: AWS <=> On-Premise
- Forest trust is different than synchronization (replication is not suppor ted)


![](https://i.imgur.com/iHoRohK.png)

### Solution Architecture: Active Directory Replication
- You may want to create a replica of your AD on EC2 in the cloud to minimize latency of in case DX or VPN goes down
- Establish trust between the AWS Managed Microsoft AD and EC2

![](https://i.imgur.com/TfOvmNp.png)


### AWS Directory Services AD Connector
- AD Connector is a directory gateway to redirect directory requests to your on-premises Microsoft Active Directory
- No caching capability
- Manage users solely on-premise, no possibility of setting up a trust
- VPN or Direct Connect
- Doesn’t work with SQL Server, doesn’t do seamless joining, can’t share directory

![](https://i.imgur.com/EDipH8Z.png)


### AWS Directory Services Simple AD

- Simple AD is an inexpensive Active Directory–compatible service with the common directory features.
- Supports joining EC2 instances, manage users and groups
- Does not support MFA, RDS SQL server, AWS SSO
- Small: 500 users, large: 5000 users
- Powered by Samba4, compatible with Microsoft AD
- lower cost, low scale, basic AD compatible, or LDAP compatibility
- No trust relationship

### AWS Organizations
- Master accounts must invite Child Accounts
- Master accounts can create Child Accounts
- Master can access child accounts using:
  - CloudFormation StackSets to create IAM roles in target accounts
  - Assume the roles using the STS Cross Account capability
- Strategy to create a dedicated account for logging or security
- API is available to automate AWS account creation
- Integration with AWS Single Sign-On (SSO)

### AWS Organizations - Features
- Consolidated billing features:
  - Consolidated Billing across all accounts - single payment method
  - Pricing benefits from aggregated usage (volume discount for EC2, S3…)
- All Features (Default):
  - Includes consolidated billing features
  - You can use SCP
  - Invited accounts must approve enabling all features
  - Ability to apply an SCP to prevent member accounts from leaving the org
  - Can’t switch back to Consolidated Billing Features only
### Multi Account Strategies
- Create accounts per department, per cost center, per dev / test / prod, based on regulatory restrictions (using SCP), for better resource isolation (ex: VPC), to have separate per-account service limits, isolated account for logging, 
- Multi Account vs One Account Multi VPC
- Use tagging standards for billing purposes
- Enable CloudTrail on all accounts, send logs to central S3 account
- Send CloudWatch Logs to central logging account
- Establish Cross Account Roles for Admin purposes

### Service Control Policies (SCP)
- Whitelist or blacklist IAM actions
- Applied at the OU or Account level
- Does not apply to the Master Account
- SCP is applied to all the Users and Roles of the Account, including Root user
- The SCP does not affect service-linked roles
  - Service-linked roles enable other AWS services to integrate with AWS Organizations 
and can't be restricted by SCPs.
- SCP must have an explicit Allow (does not allow anything by default)
- Use cases:
  - Restrict access to certain services (for example: can’t use EMR)
  - Enforce PCI compliance by explicitly disabling services

### AWS Organizations – Reserved Instances
- For billing purposes, the consolidated billing feature of AWS Organizations treats all the accounts in the organization as one account.
- This means that all accounts in the organization can receive the hourly cost benefit of Reserved Instances that are purchased by any other account.
- The payer account (master account) of an organization can turn off Reserved Instance (RI) discount and Savings Plans discount sharing for any accounts in that organization, including the payer account
- This means that RIs and Savings Plans discounts aren't shared between any accounts that have sharing turned off. 
- To share an RI or Savings Plans discount with an account, both accounts must have sharing turned on
### AWS Resource Access Manager
- Share AWS resources that you own with other AWS accounts
- Share with any account or within your Organization
- Avoid resource duplication!
- VPC Subnets: 
  - allow to have all the resources launched in the same subnets
  - must be from the same AWS Organizations. 
  - Cannot share security groups and default VPC
  - Participants can manage their own resources in there
  - Participants can't view, modify, delete resources that belong to other participants or the owner
- AWS Transit Gateway
- Route53 Resolver Rules
- License Manager Configurations
### AWS Single Sign on
- Centrally manage Single Sign-On to access multiple accounts and 3rd-party business applications. 
- Integrated with AWS Organizations
- Supports SAML 2.0 markup
- Integration with on-premise Active Directory
- Centralized permission management
- Centralized auditing with CloudTrail

### Summary
- Users and Accounts all in AWS
- AWS Organizations
- Federation with SAML
- Federation without SAML with a custom IdP (GetFederationToken)
- Federation with SSO for multiple accounts with AWS Organizations
- Web Identity Federation (not recommended) 
- Cognito for most web and mobile applications (has anonymous mode, MFA) 
- Active Directory on AWS:
  - Microsoft AD: standalone or setup trust AD with on-premise, has MFA, seamless join, RDS integration
  - AD Connector: proxy requests to on-premise
  - Simple AD: standalone & cheap AD-compatible with no MFA, no advanced capabilities
- Single Sign On to connect to multiple AWS Accounts (Organization) and SAML apps


## Security

### CloudTrail
- Provides governance, compliance and audit for your AWS Account
- CloudTrail is enabled by default!
- Get an history of events / API calls made within your AWS Account by:
- Console
- SDK
- CLI
- AWS Services
- Can put logs from CloudTrail into CloudWatch Logs
- If a resource is deleted in AWS, look into CloudTrail first!

### CloudTrail continued… 
- CloudTrail console shows the past 90 days of activity
- The default UI only shows “Create”, “Modify” or “Delete” events
- CloudTrail Trail:
  - Get a detailed list of all the events you choose
  - Can include events happening at the object level in S3
  - Ability to store these events in S3 for further analysis
  - Can be region specific or be global & include global events (IAM, etc)

### CloudTrail: How to react to events the fastest?
Overall, CloudTrail may take up to 15 minutes to deliver events
- CloudWatch Events:
  - Can be triggered for any API call in CloudTrail
  - The fastest, most reactive way
- CloudTrail Delivery in CloudWatch Logs:
  - Events are streamed
  - Can perform a metric filter to analyze occurrences and detect anomalies
- CloudTrail Delivery in S3:
  - Events are delivered every 5 minutes
  - Possibility of analyzing logs integrity, deliver cross account, long-term storage
### KMS
- Anytime you hear “encryption” for an AWS service, it’s most likely KMS
- Easy way to control access to your data, AWS manages keys for us
- Fully integrated with IAM for authorization
- Seamlessly integrated into:
  - Amazon EBS: encrypt volumes
  - Amazon S3: Server side encryption of objects
  - Amazon Redshift: encryption of data
  - Amazon RDS: encryption of data
  - Amazon SSM: Parameter store 
  - Etc… 
- But you can also use the CLI / SDK
### AWS KMS 101
- The value in KMS is that the CMK used to encrypt data can never be retrieved by the user, and the CMK can be rotated for extra security
- Never ever store your secrets in plaintext, especially in your code!
- Encrypted secrets can be stored in the code / environment variables
- KMS can only help in encrypting up to 4KB of data per call
- If data > 4 KB, use Envelope Encryption
- To give access to KMS to someone:
  - Make sure the Key Policy allows the user
  - Make sure the IAM Policy allows the API calls
- Track API calls made to KMS in CloudTrail

### Types of KMS Keys
- Customer Manager CMK:
  - Create, manage and use, can enable or disable
  - Possibility of rotation policy (new key generated every year, old key preserved)
  - Can add a key policy (resource policy)
  - Leverage for envelope encryption
- AWS managed CMK:
  - Used by AWS service (aws/s3, aws/ebs, aws/redshift)
  - Managed by AWS
### Parameter Store
- Secure storage for configuration and secrets
- Optional Seamless Encryption using KMS
- Serverless, scalable, durable, easy SDK, free
- Version tracking of configurations / secrets
- Configuration management using path & IAM
- Notifications with CloudWatch Events
- Integration with CloudFormation
- Can retrieve secrets from Secrets Manager using the SSM Parameter Store API
### Secrets Manager
- Newer service, meant for storing secrets
- Capability to force rotation of secrets every X days
- Automate generation of secrets on rotation (uses Lambda)
- Integration with Amazon RDS (MySQL, PostgreSQL, Aurora)
- Secrets are encrypted using KMS
- Mostly meant for RDS integration
### RDS Security
- KMS encryption at rest for underlying EBS volumes / snapshots
- Transparent Data Encryption (TDE) for Oracle and SQL Server
- SSL encryption to RDS is possible for all DB (in-flight)
- IAM authentication for MySQL and PostgreSQL
- Authorization still happens within RDS (not in IAM)
- Can copy an un-encrypted RDS snapshot into an encrypted one
- CloudTrail cannot be used to track queries made within RDS
### SSL Encryption, SNI(Server Name Indication) & MITM
SSL/TLS - Basics 
- SSL refers to Secure Sockets Layer, used to encrypt connections
- TLS refers to Transport Layer Security, which is a newer version
- Nowadays, TLS certificates are mainly used, but people still refer as SSL 
- Public SSL certificates are issued by Certificate Authorities (CA)
- Comodo, Symantec, GoDaddy, GlobalSign, Digicert, Letsencrypt, etc… 
- SSL certificates have an expiration date (you set) and must be renewed
### SSL – Server Name Indication (SNI)
 - SNI solves the problem of loading multiple SSL certificates onto one web server (to serve multiple websites)
- It’s a “newer” protocol, and requires the client to indicate the hostname of the target server in the initial SSL handshake
- The server will then find the correct certificate, or return the default one
Note:
- Only works for ALB & NLB (newer generation), CloudFront
- Does not work for CLB (older gen)

### SSL – Man in the Middle Attack How to prevent

- Don’t use public-facing HTTP, use HTTPS (meaning, use SSL/TLS certificates)
- Use a DNS that has DNSSEC
  - To send a client to a pirate server, a DNS response needs to be “forged” by a server which intercepts them
  - It is possible to protect your domain name by configuring DNSSEC
  - Amazon Route 53 supports DNSSEC for domain registration. 
  - Route 53 supports DNSSEC for DNS service as of December 2020 (using KMS)
  - You could also run a custom DNS server on Amazon EC2 for example (Bind is the most popular, dnsmasq, KnotDNS, PowerDNS).
### AWS Certificate Manager(Regional Service)

- To host public SSL certificates in AWS, you can:
  - Buy your own and upload them using the CLI
  - Have ACM provision and renew public SSL certificates for you (free of cost)

- ACM loads SSL certificates on the following integrations:
  - Load Balancers (including the ones created by EB)
  - CloudFront distributions
  - APIs on API Gateways

- SSL certificates is overall a pain to manually manage, so ACM is great to leverage in your AWS infrastructure

### ACM – Good to know
- Possibility of creating public certificates
  - Must verify public DNS 
  - Must be issued by a trusted public certificate authority (CA)
- Possibility of creating private certificates
  - For your internal applications
  - You create your own private CA
  - Your applications must trust your private CA
- Certificate renewal:
  - Automatically done if generated provisioned by ACM
  - Any manually uploaded certificates must be renewed manually and re-uploaded
- ACM is a regional service
  - To use with a global application (multiple ALB for example), you need to issue an SSL certificate in each region where you application is deployed. 
  - You cannot copy certs across regions
### CloudHSM(Hardware Security Module)
- KMS => AWS manages the software for encryption
- CloudHSM => AWS provisions encryption hardware
- Dedicated Hardware (HSM = Hardware Security Module)
- You manage your own encryption keys entirely (not AWS)
- HSM device is tamper resistant, FIPS 140-2 Level 3 compliance
- Supports both symmetric and asymmetric encryption (SSL/TLS keys)
- No free tier available
- Must use the CloudHSM Client Software
- Redshift supports CloudHSM for database encryption and key management
- Good option to use with SSE-C encryption

### Solution Architeture - SSL on ELB
- There are 4 methods of encrypting objects in S3
- SSE-S3: encrypts S3 objects using keys handled & managed by AWS
- SSE-KMS: leverage AWS Key Management Service to manage encryption keys
- SSE-C: when you want to manage your own encryption keys
- Client Side Encryption 
- Glacier: all data is AES-256 encrypted, key under AWS control
### Encryption in transit (SSL)

- AWS S3 exposes:
  - HTTP endpoint: non encrypted
  - HTTPS endpoint: encryption in flight
- You’re free to use the endpoint you want, but HTTPS is recommended
- HTTPS is mandatory for SSE-C
- Encryption in flight is also called SSL / TLS

### Events in S3 Buckets

- S3 Access Logs:
  - Detailed records for the requests that are made to a bucket
  - Might take hours to deliver
  - Might be incomplete (best effort)
- S3 Events Notifications:
  - Receive notifications when certain events happen in your bucket
  - E.g.: new objects created, object removal, restore objects, replication events
  - Destinations: SNS, SQS queue, Lambda
  - Typically delivered in seconds but can take minutes, notification for every object if versioning is enabled, else risk of one notification for two same object write done simultaneously
- Trusted Advisor:
  - Check the bucket permission (is the bucket public?)
- CloudWatch Events:
  - Need to enable CloudTrail object level logging on S3 first
  - Target can be Lambda, SQS, SNS, etc…
### S3 Security
- User based
  - IAM policies - which API calls should be allowed for a specific user from IAM console

- Resource Based
  - Bucket Policies - bucket wide rules from the S3 console - allows cross account
  - Object Access Control List (ACL) – finer grain
  - Bucket Access Control List (ACL) – less common

### S3 bucket policy
- Use S3 bucket for policy to:
  - Grant public access to the bucket
  - Force objects to be encrypted at upload
  - Grant access to another account (Cross Account)
- Optional Conditions on:
  - Public IP or Elastic IP (not on Private IP)
  - Source VPC or Source VPC Endpoint – only works with VPC Endpoints
  - CloudFront Origin Identity
  - MFA

### S3 pre-signed URLs

- Can generate pre-signed URLs using SDK or CLI
  - For downloads (easy, can use the CLI)
  - For uploads (harder, must use the SDK)
- Valid for a default of 3600 seconds, can change timeout with --expires-in [TIME_BY_SECONDS] argument
- Users given a pre-signed URL inherit the permissions of the person who generated the URL for GET / PUT
- Examples : 
  - Allow only logged-in users to download a premium video on your S3 bucket
  - Allow an ever changing list of users to download files by generating URLs dynamically
  - Allow temporarily a user to upload a file to a precise location in our bucket

### S3 Object Lock & Glacier Vault Lock
- S3 Object Lock
  - Adopt a WORM (Write Once Read Many) model
  - Block an object version deletion for a specified amount of time
- Glacier Vault Lock
  - Adopt a WORM (Write Once Read Many) model
  - Lock the policy for future edits (can no longer be changed)
  - Helpful for compliance and data retention
### Network Security, DDOS, Shield & WAF
- Security Groups 
  - Attached to ENI (Elastic Network Interfaces) – EC2, RDS, Lambda in VPC, etc
  - Are stateful (any traffic in is allowed to go out, any traffic out can go back in)
  - Can reference by CIDR and security group id 
  - Supports security group references for VPC peering 
  - Default: inbound denied, outbound all allowed
 - NACL (Network ACL): 
   - Attached at the subnet level 
   - Are stateless (inbound and outbound rules apply for all traffic) 
   - Can only reference a CIDR range (no hostname)
   - Default: allow all inbound, allow all outbound 
   - New NACL: denies all inbound, denies all outbound 
 - Host Firewall 
   - Software based, highly customizable
 
### Type of Attacks on your infrastructure
- Distributed Denial of Service (DDoS):
  - When your service is unavailable because it’s receiving too many requests
  - SYN Flood (Layer 4): send too many TCP connection requests
  - UDP Reflection (Layer 4): get other servers to send many big UDP requests
  - DNS flood attack: overwhelm the DNS so legitimate users can’t find the site
  - Slow Loris attack: a lot of HTTP connections are opened and maintained
- Application level attacks: 
  - more complex, more specific (HTTP level)
  - Cache bursting strategies: overload the backend database by invalidating cache
### DDoS Protection on AWS
- AWS Shield Standard: protects against DDoS attack for your website and applications, for all customers at no additional costs
- AWS Shield Advanced: 24/7 premium DDoS protection
- AWS WAF: Filter specific requests based on rules
- CloudFront and Route 53: 
  - Availability protection using global edge network
  - Combined with AWS Shield, provides DDoS attack mitigation at the edge
- Be ready to scale – leverage AWS Auto Scaling
- Separate static resources (S3 / CloudFront) from dynamic ones (EC2 / ALB)
- Read the whitepaper for details: 
https://d1.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf
### AWS Shield
- AWS Shield Standard:
  - Free service that is activated for every AWS customer
  - Provides protection from attacks such as SYN/UDP Floods, Reflection attacks and other layer 3/layer 4 attacks
- AWS Shield Advanced: 
  - Optional DDoS mitigation service ($3,000 per month per organization) 
  - Protect against more sophisticated attack on Amazon EC2, Elastic Load Balancing (ELB), Amazon CloudFront, AWS Global Accelerator, and Route 53
  - 24/7 access to AWS DDoS response team (DRP)
  - Protect against higher fees during usage spikes due to DDoS
### AWS WAF – Web Application Firewall
- Protects your web applications from common web exploits (Layer 7)
- Deploy on Application Load Balancer (localized rules) 
- Deploy on API Gateway (rules running at the regional or edge level)
- Deploy on CloudFront (rules globally on edge locations)
  - Used to front other solutions: CLB, EC2 instances, custom origins, S3 websites)
- WAF is not for DDoS protection
- Define Web ACL (Web Access Control List):
  - Rules can include: IP addresses, HTTP headers, HTTP body, or URI strings
  - Protects from common attack - SQL injection and Cross-Site Scripting (XSS)
  - Size constraints, Geo match
  - Rate-based rules (to count occurrences of events)
### AWS Firewall Manager
- Manage rules in all accounts of an AWS Organization
- Common set of security rules
- WAF rules (Application Load Balancer, API Gateways, CloudFront)
- AWS Shield Advanced (ALB, CLB, Elastic IP, CloudFront)
- Security Groups for EC2 and ENI resources in VPC
### Blocking an IP address
ALB have security group as well
NLB didn't have security group 
If you use Cloudfront to route your internet, NACL is not useful
because cloudfront is outside of VPC! So you could use WAF or Geo-Restriction to restrict it.

### AWS Inspector
- Only for EC2 instances (started from an AMI)
- Analyze the running OS against known vulnerabilities
- Analyze against unintended network accessibility
- AWS Inspector Agent must be installed on OS in EC2 instances
- Define template (rules package, duration, attributes, SNS topics)
- No own custom rules possible – only use AWS managed rules
- After the assessment, you get a report with a list of vulnerabilities
### AWS Config
- Helps with auditing and recording compliance of your AWS resources
- Helps record configurations and changes over time
- AWS Config Rules does not prevent actions from happening (no deny)
- Questions that can be solved by AWS Config: 
  - Is there unrestricted SSH access to my security groups?
  - Do my buckets have any public access?
  - How has my ALB configuration changed over time?
- You can receive alerts (SNS notifications) for any changes
- AWS Config is a per-region service
- Can be aggregated across regions and accounts

### AWS Config Rules
- Can use AWS managed config rules (over 75)
- Can make custom config rules (must be defined in AWS Lambda)
  - Evaluate if each EBS disk is of type gp2
  - Evaluate if each EC2 instance is t2.micro
- Rules can be evaluated / triggered:
  - For each config change
  - And / or: at regular time intervals
  - Can trigger CloudWatch Events if the rule is non-compliant (and chain with Lambda)
- Rules can have auto remediations:
  - If a resource is not compliant, you can trigger an auto remediation
  - Define the remediation through SSM Automations
  - Ex: remediate security group rules, stop instances with non-approved tags
### AWS Managed Logs
- Load Balancer Access Logs (ALB, NLB, CLB) => to S3
  - Access logs for your Load Balancers
- CloudTrail Logs => to S3 and CloudWatch Logs
  - Logs for API calls made within your account 
- VPC Flow Logs => to S3 and CloudWatch Logs
  - Information about IP traffic going to and from network interfaces in yourVPC 
- Route 53 Access Logs => to CloudWatch Logs
  - Log information about the queries that Route 53 receives 
- S3 Access Logs => to S3
  - Server access logging provides detailed records for the requests that are made to a bucket 
- CloudFront Access Logs => to S3
  - Detailed information about every user request that CloudFront receives 
- AWS Config => to S3
### AWS GuardDuty
- Intelligent Threat discovery to Protect AWS Account 
- Uses Machine Learning algorithms, anomaly detection, 3rd party data
- One click to enable (30 days trial), no need to install software
- Input data includes:
  - CloudTrail Logs: unusual API calls, unauthorized deployments
  - VPC Flow Logs: unusual internal traffic, unusual IP address
  - DNS Logs: compromised EC2 instances sending encoded data within DNS queries
- Can setup CloudWatch Event rules to be notified in case of findings
- CloudWatch Events rules can target AWS Lambda or SNS


## Compute & Load Balancing

### Solutions Architeture on AWS
![](https://i.imgur.com/VdxOZjf.jpg)


### EC2 Instance Types - Main ones

- Ｒ：applications that needs a lot of RAM -in memory caches
- Ｃ: applications that needs good CPU  compute/database
- Ｍ：applications that are balanced (think "medium")-general web-app
- I: applications that need good local I/O(instance storage) -databases
- G: applications that need a GPU - video rendering / machine learning 
- T2/T3: burstable instances(up to a capacity)
- T2/T3 - unlimited: unlimited burst
- On Demand Instances: short workload, predictable pricing, reliable.
- Spot Instance: short workloads, for cheap, can lose instances(not reliable)
- Reserved(Minimum 1 year)
  - Reserved Instances: long workloads
  - Convertible Reserved Instances: Long workloafs with flexible instances
  - Scheduled Reserved Instances: example-every Thursday between 3 and 6 pm
- Dedicated Instances: no other customers will share your hardware
- Dedicated Hosts: book an entire physical server, control instance placement 
   - Greate for software license that operate at the core, or CPU socket level.
   - Can define host affinity so that instance reboots are lept on the same host.
- RAM is note included in EC2

### EC2 - Placement Groups
`By default your ec2 would be put randomly!`
`You can tell or hint aws where you wanna place `
- Control the EC2 Instance placement strategy using placement groups
- Group Strategies: 
  - Cluster—clusters instances into a low-latency group in a single Availability Zone(same az good for HPC(high performance compute))
  - Spread—spreads instances across underlying hardware (max 7 instances per group per AZ) – critical applications
  - Partition—spreads instances across many different partitions (which rely on different sets of racks) within an AZ. Scales to 100s of EC2 instances per group (Hadoop, Cassandra, Kafka)
- You can move an instance into or out of a placement group
  - Your first need to stop it
  - You then need to use the CLI (modify-instance-placement) 
  - You can then start your instance

### Placement Groups have different policy

### EC2 Instance Launch Types
- On Demand Instances: short workload, predictable pricing, reliable
- Spot Instances: short workloads, for cheap, can lose instances (not reliable)
- Reserved: (MINIMUM 1 year)
  - Reserved Instances: long workloads 
  - Convertible Reserved Instances: long workloads with flexible instances
  - Scheduled Reserved Instances: example – every Thursday between 3 and 6 pm
- Dedicated Instances: no other customers will share your hardware
- Dedicated Hosts: book an entire physical server, control instance placement
  - Great for software licenses that operate at the core, or CPU socket level
  - Can define host affinity so that instance reboots are kept on the same host

### EC2 included metrics
- CPU: CPU Utilization + Credit Usage / Balance 
- Network: Network In / Out 
- Status Check: 
  - Instance status = check the EC2 VM 
  - System status = check the underlying hardware 
- Disk: Read / Write for Ops / Bytes (only for instance store) 
- RAM is NOT included in the AWS EC2 metric

### Auto Scaling - Scaling Policies

- Simple / Step Scaling: increase or decrease instances based on two CW alarms
- Target Tracking: select a metric and a target value, ASG will smartly adjust
  - Keep average CPU at 40%
  - Keep request count per target at 1000
- To scale based on RAM, you must use a Custom CloudWatch Metric
### Auto Scaling - Good to know
- Spot Fleet support (mix on Spot and On-Demand instances)
- To upgrade an AMI, must update the launch configuration / template
  - You must terminate instances manually
  - CloudFormation can help with that step (we’ll see it later)
- Scheduled scaling actions:
  - Modify the ASG settings (min / max / desired) at pre-defined time
  - Helpful when patterns are known in advance
- Lifecycle Hooks:
  - Perform actions before an instance is in service, or before it is terminated
  - Examples: cleanup, log extraction, special health checks

### Auto Scaling - Scaling Process
- Launch: Add a new EC2 to the group, increasing the capacity
- Terminate: Removes an EC2 instance from the group, decreasing its capacity.
- HealthCheck: Checks the health of the instances
- ReplaceUnhealthy:Terminate unhealthy instances and re-create them
- AZRebalance: Balancer the number of EC2 instances across AZ
- AlarmNotification: Accept notification from CloudWatch
- ScheduledActions: Performs scheduled actions that you create.
- AddToLoadBalancer: Adds instances to the load balancer or target group
- We can suspend these processes!

### Spot Instance & Spot Fleet 
- Can get a discount of up to 90% compared to On-demand
- Define max spot price and get the instance while current spot price < max 
  - The hourly spot price varies based on offer and capacity
  - If the current spot price > your max price you can choose to stop or terminate your instance with a 2 minutes grace period.
- Other strategy: Spot Block
  - “block” spot instance during a specified time frame (1 to 6 hours) without interruptions
  - In rare situations, the instance may be reclaimed
- Used for batch jobs, data analysis, or workloads that are resilient to failures. 
- Not great for critical jobs or databases

### ECS- Elastic Container Service


### AWS Lambda part1

### AWS Lambda part2

### Elastic Load Balancer

### API Gateway


### Route53 part1

![](https://i.imgur.com/jcoNJja.png)
### Route53 part2


Health Checks-
Can be set up to pass / fail based on text in the frist 5120 bytes of the response

Only pass 2xx and 3xx

Health check can trigger CW alarm.

Health check can't access private endpoints
![](https://i.imgur.com/MeaVZdE.png)


### Comparison of Solutions Architecture
- EC2 on its own with Elastic IP
- EC2 with Route53
   - DNS Based load-balancing
   - Ability to use multiple instance
   - Route53 TTL implies client may get outdated information
   - Clients May have some logic to deal with hostname resolution failures.
   - Adding an instance may not receive full trafic right away due to DNS TTL
- ALB + ASG
   - ALB is elastic but can't handle sudden, huge peak of demand (pre-warm)
   - Could lost a few request if instance ar overloaded
   - CW used for scaling
   - Cross-Zone balancing for even traffic
   - Target ultilization 40%-70%
- ALB + ECS on EC2
   - Tough to orchestrate ECS service autoscaling + ASG auto sclaing
- ALB + ECS on Fargate
   - Fargate have service auto scaling and is easy
- ALB +Lambda
   - Simple way to expose lambda fucntion as HTTP/S without all the features from API Gateway
   - Good for hybrid microservices

- API Gateway + Lambda
   - Soft limit: 10000/s API Gateway, 1000 concurrent lambda
   - API Gateway features: authentication, rate limiting, caching, etc
   - Lambda cold start
- API Gateway + AWS Service+ SQS
  - Better to use API Gateway + SQS 
- API Gateway + HTTP backend(ex:ALB)
  - Use API Gateway features on top of custom HTTP backend(authentication, rate control, API keys, caching)
  - Can connect to
  - On-premise service
  - ALB
  - 3rd party HTTP service.
 
## Storage

### EBS
- Network drive you attach to ONE instance only
- Linked to a specfic availability zone (transfer:snapshot => restore)
- Volumes can be resized
- Make sure you choose an instance type that is EBS optimized to enjoy maximum throughput.

### EBS - Volume Types
- gp2: General Purpose Volumes(cheap)
   - 3 IOPS/GiB, minimum 100 IOPS, burst to 3000IOPS, max 16000 IOPS
   - 1 GiB - 16TiB, + 1TB=+3000 IOPS
   
- iol:Provisioned IOPS(expensive)
  - Min 100 IOPS, Max 64000 IOPS(Nitro) or 32000(other)
  - 4 GiB - 16 TiB. Size of volume and IOPS are independent

- stl: Throughput Optimized HDD
  - 500 GiB - 16TiB, 500 MiB/s throughput
- scl: Cold HDD, Infrequently accessed data
  - 250 GiB - 16 TiB, 250 MiB /s throughput

### EBS - RAID Configurations


### EBS Snapshots
- Incremental - only backup changed blocks
- EBS backups use IO and you shouldn't run them while your application is handling a lot of traffic
- Snapshots will be stored in S3(but you won't directly see them)
- Not necessary to detach volume to do snapshot, but recommended
- Can copy snapshots across region(for DR)
- Can make Image(AMI)from Snapshot
- EBS volumes restored by snapshots need to be pre-warmed (using fio or dd command to read entire volume)
- Snapshots can be automated using Amazon Data Lifecycle Manager

### Local EC2 Instance Store
- Physical disk attached to the physical server where your EC2 is
- Very High IOPS(because physical)
- Disks up to 7.5TiB(can change over time), stripped to reach 30 TiB(can change over time)
- Block Storage (just like EBS)
- Cannot be increased in size
- Risk of data loss if hardware fails

### EBS v.s Instance Store
- Some instance do not come with Root EBS volumes
- Instead, they come with "Instance Store"(=ephemeral storage)
- Instance store is physically attached to the machine(EBS is a network drive)
- Pros:
   - Better I/O performance(EBS gp2 has an max IOPS of 16000, io l of 64000)
   - Good for buffer / cache / scratch data / temporary content
   - Data Survives reboots
- Cons:
   - On stop or termination, the instance store is lost
   - You can't resize the instance store
   - Backups must b operated by the user
   
### EFS - Elastic File System
- Use cases: content management, web serving, data sharing, Wordpress
- Compatible with Linux based AMI(not windows),POSIX-compliant
- Uses NFSv4.1 protocol
- Uses security group to control access to EFS
- Encryption at rest using KMS
- Can only attach to one VPC, create one ENI(mount target)per AZ

### EFS- Performance & Storage Classes
- EFS Scale
  - 1000s of concurrent NFS clients, 10GB +/s throughput
  - Grow to Petabyte-scale network file system


- Performance mode(set at EFS creation time)
  - General purpose(default):latency-sensitive use cases(web server, CMS, etc...)
  - Max I/O - higher latency, higher throughput highly parallel(big data, media processing)
 
- Throughput Mode
  - Bursting Mode: common for filesystems(intensive work, then almost nothing), linked to FS size
  - Provisioned IO Mode: high throughput to storage ration(if burst is not enough) - expensive

- Storage Tiers(lifecycle management feature - move file after N days)
  - Standard: for frequently accessed file
  - Infrequently access: higher cost to retrieve the file,lower price point to store the file.

### S3

- Object storage, serverless, unlimited storage, pay as you go
- Good to store static content(image, video files)
- Accesso objecy by key, no indexing facility
- Not a filesystem, cannot be mounted natively on EC2
- **Anti patterns**:
  - Lost of small files
  - POSIX file system (use EFS instead), file locks
  - Search feature, queries, rapidly changing data

### S3-replication
- Cross Region Replication(CRR)
- Same Region Replication(SRR)
- Combine with Lifecycle Polices
---
- Helpful to reduce latency
- Helpful for disaster recovery
- Helpful for security
- S3 bucket versioning must be enabled

### S3 Events Notifications
- **S3:ObjectCreated, S3:ObjectRemoved,
  S3:ObjectRestored,S3:Replication**
- Object name filtering possible(*.jpg)
- Use case: generate thumbnails of images uploaded to S3
- S3 event notifications typically deliver events in seconds but can sometimes take a minute or longer
- If two writes are made to a single non-versioned object at the same time, it is possible that only a single event notification will be sent
- If you want to ensure that an event notificayion is sent for every successful write, you can enable versioning on your bucket.

### S3 - Cloudwatch Events
- By default, CloudTrail records S3 bucket level API calls
- Cloudtrail logs for object-level Amazon S3 actions can be enabled
- This help us generate events for object-level API(GetObject, PutObject, DeleteObject, PutObjectAcl,etc...)

### S3 - Baseline Performance
- Amazon S3 automatically scales to high requests rates, latency 100-200ms
- Your application can achieve at least 3,500 PUT/COPY/POST/DELETE and 5,500 GET/HEAD requests per second per prefix in a bucket
- Example(object pah => prefix):
  - bucket/folder1/sub1/file => /folder1/sub1/
  - bucket/folder1/sub2/file => /folder1/sub2/
  - bucket/1/file            => /1/
  - bucket/2/file            => /2/
- If you spread reads across all four prefixes evenly, you can achieve 22,000 requests per second for GET and HEAD

#### S3 Performance
- Multi-Part upload:
  - recommended for files > 100MB,
    must use for files > 5GB
  - Can help parallelize uploads(speed up transfer)
- S3 Transfer Acceleration (upload only)
  - Increase transfer speed by transferring file to an AWS Edge location which will forward the data to the S3 buckey in the target region
  - Compatible with muli-part upload
#### S3 Performance - S3 Byte-Range Fetches
- Parallelize GETs by requesting specific byte ranges
- Better resilience in case of failures

Can be used to speed up downloads

Can be used to retrieve only partial data(for example the head of a file)

#### S3 Select & Glacier Select
- Retrieve less data using SQL by perform by **server side filtering**
- Can filter by rows & columns (simple SQL statements)
- Less network transfer, less CPU cost client-side

### S3 Solution Architecture Exposing static Objects
picture


## Caching

### Cloudfront-Part 1

### Cloudfront-Part 2

### Cloudfront-Part 3

### Cloudfront-Part4

### Amazon ElastiCache

### Handling Extreme Rates

## Databases

### DynamoDB - in short
- NoSQL database, fully managed, massive scale(1,000,000 rps)
- Similar to Apache Cassandra (can migrate to DynamoDB)
- No disk space to provision, max object size is 400KB
- Capacity:provisioned (WCU,RCU, &Auto Scaling)or on-demand
- Supports CRUD(Create Read Update Delete)
- Read:eventually or strong consistency
- Supports transactions across mutiple tables(ACID support)
- Backups available, point in time recovery
- Integrated with IAM for security

### DynamoDB Basics
- DynamoDB is made of tables
- Each table has a primary key(must be decided at creation time)
- Each table can have an infinite number of items(=rows)
- Each item has attributes(can be added over time - can be full)
- Maximum size of a item is 400KB
- Data types supported are:
  - Scalar Types: String,Number,Binary,Boolean,Null
  - Document Types:List,Map
  - Set Types: Sring Set, Number Set, Binary Set

### DynamoDB - Primary Keys
- **Option 1: Partition key only (HASH)**
- Partition key must be unique for each item
- Partition key must be “diverse” so that the data is distributed
- Example: user_id for a users table
- **Option 2: Partition key + Sort Key**
- The combination must be unique
- Data is grouped by partition key
- Sort key == range key
- Example: users-games table 
   - user_id for the partition key 
   - game_id for the sort key
- Example good sort key: timestamp

### DynamoDB – Indexes
- Object = primary key + optional sort key + attributes
- LSI – Local Secondary Index
  - Keep the same primary key
  - Select an alternative sort key
  - Must be defined at table creation time
- GSI – Global Secondary Index
   - Change the primary key and optional sort sort 
   - Can be defined after the table is created
   
 - You can only query by PK + sort key on the main table & indexes (≠ RDS)
  
### DynamoDB – Important Features
 - TTL: automatically expire row after a specified epoch date
 - DynamoDB Streams:
   - react to changes to DynamoDB tables in real time
   - Can be read by AWS Lambda, EC2... 
   - 24 hours retention of data

 - Global Tables: (cross region replication)
   - Active Active replication, many regions
   - Must enable DynamoDB Streams
   - Useful for low latency, DR purposes
 
### DynamoDB - DAX
 - DAX = DynamoDB Accelerator
 - Seamless cache for DynamoDB, no application re- write
 - Writes go through DAX to DynamoDB
 - Micro second latency for cached reads & queries
 - Solves the Hot Key problem (too many reads)
 -  5 minutes TTL for cache by default
 -  Up to 10 nodes in the cluster
 -  Multi AZ (3 nodes minimum recommended for production)
 -  Secure (Encryption at rest with KMS,VPC, IAM, CloudTrail...)

DAX -Individual objects cache Query / Scan cache
ElasticCache- Store Aggregation Result, heavy-lifting computing

### Amazon ElasticSearch
- May be called Amazon ES at the exam
- Managed version of ElasticSearch (open source project)
- Needs to run on servers (not a serverless offering)
- Use cases:
  - Log Analytics
  - Real Time application monitoring
  - Security Analytics
  - FullTextSearch
  - Clickstream Analytics
  - Indexing

### ElasticSearch + Kibana + Logstash
- ElasticSearch: provide search and indexing capability
  - You must specify instance types, multi-AZ, etc
- Kibana:
  - Provide real-time dashboards on top of the data that sits in ES
  - Alternative to CloudWatch dashboards (more advanced capabilities)

- Logstash:
  - Log ingestion mechanism, use the “Logstash Agent”
  - Alternative to CloudWatch Logs (you decide on retention and granularity)

### RDS

#### Aurora


## Service Communication(finished)

### Step Functions


### SWF


### SQS 

* Serverless, managed queue, integrated with IAM
* Can handle extreme scale, no provisioning required
* Use to **decoupled** service
* Message size of max 256 KB (use a pointer to S3 for large messages)
* Can be read from EC2 (optional ASG), Lambda
* SQS could be used as a write buffer for DynamoDB
* SQS FIFO:
   * receive messages in order they were sent
   * 300 messages/s without batching, 3000 /s with batching
* U can set up your own DLQ to provision the failure messages and analyze why it would fail.


### Amazon MQ
* When migrating to the cloud, instead of re-engineering the application to use SQS and SNS, we can use Amazon MQ
* Amazon MQ = managed Apache ActiveMQ
* Amazon MQ doesn’t “scale” as much as SQS / SNS
* Amazon MQ runs on a dedicated machine, can run in HA with failover
* Amazon MQ has both queue feature (~SQS) and topic features (~SNS)

### SNS

* The “event producer” only sends message to one SNS topic
* As many “event receivers” (subscriptions) as we want to listen to the SNS topic notifications
* Each subscriber to the topic will get all the messages (note: new feature to filter messages)
* Up to 10,000,000 subscriptions per topic
* 100,000 topics limit
* Subscribers can be:
  - SQS
  - HTTP / HTTPS (with delivery retries – how many times)
  - Lambda
  - Emails
  - SMS messages
  - MobileNotifications(SNSMobilePush Android,Apple,FireOS,Windows...)



## Data Engineering
### Kinesis Data Streams
- Kinesis is a managed “data streaming” service
- Great for application logs, metrics, IoT, clickstreams
- Great for “real-time” big data
- Great for streaming processing frameworks (Spark, NiFi, etc...) - Data is automatically replicated synchronously to 3 AZ
- **Kinesis Streams**: low latency streaming ingest at scale
- **Kinesis Analytics**: perform real-time analytics on streams using SQL
- **Kinesis Firehose**: load streams into S3, Redshift, ElasticSearch & Splunk

### Kinesis Streams Overview
- Streams are divided in order Shards/Partitions 
- Data retention is 24 hours by default, can go up to 7 days 
-  Ability to reprocess / replay data
- Multiple applications can consume the same stream
- Real-time processing with scale of throughput
- Once data is inserted in Kinesis, it can’t be deleted (immutability)

### Kinesis Streams Shards
- One stream is made of many different shards
- Billing is per shard provisioned, can have as many shards as you want 
- Batching available or per message calls.
- The number of shards can evolve over time (reshard / merge)
- Records are ordered per shard
### Kinesis Data Streams limit to know
- Producer:
  - 1MB/s or 1000 messages/s at write PER SHARD 
  - “ProvisionedThroughputException” otherwise
- Consumer Classic:
  - 2MB/s at read PER SHARD across all consumers
  - 5 API calls per second PER SHARD across all consumers
- Consumer Enhanced Fan-Out:
  - 2MB/s at read PER SHARD, PER ENHANCED CONSUMER 
  - No API calls needed (push model)
- Data Retention:
  - 24 hours data retention by default 
  - Can be extended to 7 days
### Kinesis Data Firehose
 - Fully Managed Service, no administration, automatic scaling, serverless 
   - AWS: Redshift / Amazon S3 / ElasticSearch
   - 3rd party partner: Splunk / MongoDB / DataDog / NewRelic /
   - Custom: send to any HTTP endpoint
- Pay for data going through Firehose
- Near Real Time
  - 60 seconds latency minimum for non full batches 
  - Or minimum 32 MB of data at a time
 - Supports many data formats, conversions, transformations, compression 
 - Supports custom data transformations using AWS Lambda
 - Can send failed or all data to a backup S3 bucket

### Firehose Buffer Sizing
- Firehose accumulates records in a buffer
- The buffer is flushed based on time and size rules
- Buffer Size (ex: 32MB): if that buffer size is reached, it’s flushed
- Buffer Time (ex: 1 minute): if that time is reached, it’s flushed
- Firehose can automatically increase the buffer size to increase throughput
- High throughput => Buffer Size will be hit • Low throughput => Buffer Time will be hit
- If real-time flush from Kinesis Data Streams to S3 is needed, use Lambda

### Kinesis Data Streams vs Firehose
- Kinesis Data Streams
  - Streaming ser vice for ingest at scale
  - Write custom code (producer /consumer)
  - Real-time (~200 ms)
  - Manage scaling (shard splitting / merging)
  - Data storage for 1 to 365 days
  - Supports replay capability
### Kinesis Data Analytics

### Streaming Architecture (very important)

![](https://i.imgur.com/HYy719F.png)

### AWS Batch

### Amazon EMR

### Running Jobs on AWS

### Redshift 

### Athena & Quicksight

### Big Data Architeture




## Monitoring(finished)

### CloudWatch

### X-Ray


## Deploy and instance Management(today)

### Elastic Beanstalk

### OpsWorks

### CodeDeploy

### Cloudformation

### Service Catalog
Less control of user, more control to admin
### SAM - Serverless Application Model

### Deployment Comparison

### AWS System Manager --SSM(***)
AWS-RunPatchBaseline applies to both Windows and Linux, and AWS-DefaultPatchBaseline is the name of the default Windows patch baseline

Windows didn't have pathc line.
## Cost Control
### Cost Allocation Tags
- With Tags we can track resources that relate to each other
- With Cost Allocation Tags we can enable detailed costing repor ts 
- Just like Tags, but they show up as columns in Reports
- AWS Generated Cost Allocation Tags
  - Automatically applied to the resource you create
  - Starts with Prefix aws: (e.g. aws: createdBy)
  - They’re not applied to resources created before the activation
- User tags
  - Defined by the user
  - Starts with Prefix user:
- Cost Allocation Tags just appear in the Billing Console
- Takes up to 24 hours for the tags to show up in the report

### Trusted Advisor
- No need to install anything – high level AWS account assessment
- Analyze your AWS accounts and provides recommendation:  
  - Cost Optimization & Recommendations
  - Performance
  - Security
  - Fault Tolerance 
  - Service Limits
- Core Checks and recommendations – all customers
- Can enable weekly email notification from the console
- Full Trusted Advisor – Available for Business & Enterprise support plans 
  - Ability to set CloudWatch alarms when reaching limits
  - Programmatic Access using AWS Support API
### Trusted Advisor Good To Know
- Can check if an S3 bucket is made public
   - But cannot check for S3 objects that are public inside of your bucket!
   - Use CloudWatch Events / S3 Events instead

- Service Limits
  - Limits can only be monitored in Trusted Advisor (cannot be changed)
  - Cases have to be created manually in AWS Support Centre to increase limits
  - OR use the new AWS Service Quotas service (new service - has an API)
### EC2 Launch Types & Saving Plan
- On Demand Instances: short workload, predictable pricing, reliable
- Spot Instances: short workloads, for cheap, can lose instances (not reliable)
   - Reserved: (MINIMUM 1 year)
   - Reserved Instances: long workloads
   - Convertible Reserved Instances: long workloads with flexible instances
   - Scheduled Reserved Instances: example – everyThursday between 3 and 6 pm
- Dedicated Instances: no other customers will share your hardware
- Dedicated Hosts: book an entire physical server, control instance placement
- Great for software licenses that operate at the core, or socket level
- Can define host affinity so that instance reboots are kept on the same host

### Saving Plan
- New pricing model to get a discount based on long-term usage
- Commit to a certain type of usage: ex $10 per hour for 1 to 3 years 
- Any usage beyond the savings plan is billed at the on-demand price
- EC2 Instance Savings plan (up to 72% - same discount as Standard RIs)
  - Select instance family (e.g. M5, C5...), and locked to a specific region
  - Flexible across size (m5.large to m5.4xlarge), OS (Windows to Linux), tenancy (dedicated or default)
- Compute Savings plan (up to 66% - same discount as Convertible RIs)
  - Ability to move between instance family (move from C5 to M5), region (Ireland to US), compute type (EC2, Fargate, Lambda), OS & tenancy
### S3 Cost Savings
### S3 Storage Classes
- Amazon S3 Standard - General Purpose
- Amazon S3 Standard-Infrequent Access (IA) • Amazon S3 One Zone-Infrequent Access
- Amazon S3 Intelligent Tiering
- Amazon Glacier
- Amazon Glacier Deep Archive
- Amazon S3 Reduced Redundancy Storage (deprecated - omitted)

### Other Cost Savings
- S3 Select & Glacier Select: save in network and CPU cost 
- S3 Lifecycle Rules: transition objects between tiers
- Compress objects to save space
- S3 Requester Pays:
  - In general, bucket owners pay for all Amazon S3 storage and data transfer costs associated with their bucket
  - With Requester Pays buckets, the requester instead of the bucket owner pays the cost of the request and the data download from the bucket
  - The bucket owner always pays the cost of storing data
  - Helpful when you want to share large datasets with other accounts
  - If an IAM role is assumed, the owner account of that role pays for the request







## Migration 


### Storage Gateway

- Bridge between on-premise data and cloud data in S3
- Use cases: disaster recovery, backup & restore, tiered storage
- 3 types of Storage Gateway: 
  - File Gateway
  - Volume Gateway 
  - Tape Gateway
- Exam Tip:You need to know the differences between all 3!

  


### Volume Gateway
- Block storage using iSCSI protocol backed by S3
- **Cached volumes**:low latency access to most **recent data**, full data on S3
- **Stored volumes**:entire dataset is on-premise, scheduled backups to S3
- Can create EBS snapshots from the volumes and restore as EBS!
- Up to 32 volumes per gateway
   - Each volume up to 32 TB in cahced mode(1PB per Gateway)
   - Each volume up to 16 TB in stored mode(512TB per Gateway)

### Tape Gateway

- Some companies have buckup processes using physical tapes
- With Tape Gateway, companies use the same processes but in the cloud
- Virtual Tape Library (VTL) baced by Amazon S3 and Glacier
- Back up data using existing tape-based processes(and iSCSI interface)
- Works with leading backup software vendors
- **You can't access single file within tapes. You need to restore the tape entirely**

---
### Snowball 
* Physical data transport solution that helps moving TBs or PBs data in or out of AWS
* Alternative to moving data over the network (and paying network fees)
* Secure, tamper resistant, uses KMS 256 bit encyption
* Tracking using SNS and text message. E-ink shipping label
* Snowball size: 50TB and 80TB
* Use cases: large data cloud migrations, DC decommison, disaster recovery
* If it takes more than a week to transfer over the network, use Snowball devices!

### Snowball Process
* Request snowball devices from the AWS console for delivery.
* Install the snowball client on your servers
* Connect the snowball to your servers and copy files using the client
* Ship back the device when you're done(goes to the right AWS facility)
* Data will be loaded into an S3 bucket
* Snowball is completely wiped
* Tracking is done using SNS, text messages and the AWS console

### Snowball v.s Direct Upload

- Direct upload to S3:
- With snowball


### Snowball Edge
- Snowball Edges add computational capability to the device
- 100TB capacity with either:
  - Storage optimized-24 vCPU
  - Compute optimized-52 vCPU & optional GPU
- Supports a custom EC2 AMI so you can perform processing on the go
- Supports custom Lambda functions
- Very useful to pre-process the data while moving
- Use case: data migration, image collation, IoT capture, machine learning

### AWS Snowmobile

- Transfer exabytes of data( 1EB = 1,000 PB = 1,000,000TBs)
- Each Snowmobile has 100 PB of capacity(use multiple in parallel)
- Better than Snowball if you transfer more than 10 PB
---
### DMS - Data Migraiton Service
- Quickly and securely migrate databases to AWS, resilient, self healing
- The source database remains available during the migration
- Supports:
  - Homogeneous migrations:ex Oracle to Oracle
  - Heterogeneous migrations:ex Microsoft SQL Server to Aurora
- Continuous Data Replication using CDC
- You must create an EC2 instance to perform the replication tasks


### DMS Sources and Targets

SOURCES:
- On-Premise and EC2 instances databases: Oracle, MS SQL Server, MySQL, MariaDB, Postgre SQL, MongoDB, SAP, DB2
- Azure: Azure SQL Database
- Amazon RDS: all including Aurora
- Amazon S3

Targets:
- On-Premise and EC2 instances databases: Oracle, MS SQL Server, MySQL, MariaDB, PostgreSQL, SAP
- Amazon RDS
- Amazon Redshift
- Amazon DynamoDB
- Amazon S3
- ElasticSearch Service
- Kinesis Data Streams
- DocumentDB
(it cann't be export as resoures)



### AWS Schema Coversion Tool(SCT)
- Convert your Database's Schema from one engine to another
- Example OLTP:(SQL server or Oracle) to MySQL,PostgreSQL,Aurora
- Example OLAP:(Teradata or Oracle) to Amazon Redshift
- You do not need to use SCT if you are migrating the same DB engine
  - Ex: On-Premise PostgreSQL => RDS PostgreSQL
  - The DB engine is still PostgreSQL(RDS is the platform)

### DMS - Good things to know

- Works over VPC Peering, VPN(site to site, software), Direct Connect
- Supports Full Load, Full Load + CDC,or CDC only
- Oracle:
  - Source: Supports TDE for the source using "BinaryReader"
  - Target:Supports BLOBs in tables that have a primary key, and TDE
- ElasticSearch:
  - Source: does not exist
  - Target: possible to migrate to DMS from a relational database
  - Therefore DMS cannot be used to replicate ElasticSearch data

### Snowball + Database Migration Service (DMS)

- Larger data migrations can include many terabytes of information
- Can be limited due to network bandwidth or size of data
- AWS DMS can use Snowball Edge & Amazon S3 to speed up migration
- Following stages:
  1. You can use the AWS Schema Covertion Tool(AWS SCT) to extract the data locally and move it to an Edge device.
  2. You ship the Edge device or devices back to AWS.
  3. After AWS receives your shipment, the Edge device automatically loads its data into an Amazon S3 bucket
  4. AWS DMS takes the files and migrate the data to the target data store. If you are using change data capture(CDC), those updates are written to the Amazon S3 bucket and then applied to the target data store

### Application Discovery Services

- Plan migration projects by gathering information about on-premises data centers
- Server utilization data and dependency mapping are important for migrations
- **Agentless discovery(Application Discovery Agentless Connector):**
  - Open Virtual Appliance(OVA)package that can be deployed to a VMware host
  - VM inventory, configuration,and performance history such as CPU, memory, and disk usage
  - OS agnostic
- **Agent-based dicovery:**
  - system configuration, system performance, running processes, and details of the network connections between systems
  - Suppots Microsoft server, Amazon Linux, Ubuntu, RedHat, CentOS,SUSE
- Resulting data can be exported as CSV or viewed within AWS Migration Hub
- Data can be explorer using pre-defined queries in Amazon Athena

### AWS Server Migration Service(SMS)

- Migrate entire VMs to AWS, improvement over EC2 VM Import/Export service
- That means the OS, the data, everything is kept intact
- After loading the VM onto EC2, then you can update the OS, the data, make an AMI
- Therefore SMS is used to Re-host
- Only works with VMware vSphere,Windows Hyper-V, and Azure VM
- Every replication creates an EBS snapshot / AMI ready for deployment on EC2
- Every replication is incremental
- One time migrations, or replication every interval option

### On-Premise strategy with AWS
- Ability to download Amazon Linux 2 AMI as a VM(.iso format)
  - VMWare, KVM, VirtualBox(Oracle VM), Microsoft Hyper-V
- AWS Application Discovery Sevice
  - Gather information about your on-premise servers to plan a migration
  - Server utilization and dependency mappings
  - Track with AWS Migration Hub

- AWS VM Import/Export
  - Migrate existing application into EC2
  - Create a DR repository strategy for your on-premise VMs
  - Can export back the VMs from EC2 to on-premise
- AWS Server Migration Service(SMS)
  - Incremental replication of on-premise live servers to AWS
  - Migrates entire VM into AWS
- AWS Database Migration Service(DMS)
  - replicate On-premise => AWS, AWS => AWS, AWS => On-premise
  - Works with various database technologies(Oracle, MySQL, DynamoDB, etc......)



### Disaster Recovery (very very important)
- Any event that has a negative impact on a company's business continuity or finance is a disaster
- Disaster recovery(DR) is about preparing for and recovering from a disaster
- What kind of disaster recovery?
   - On-premise => On-premise:traditional DR, and very expensive
   - On-premise => AWS Cloud:hybrid recovery
   - AWS Cloud Region A => AWS Cloud Region B
- Need to define two terms:
    - RPO: Recovery Point Objective
    - RTO: Recovery Time Objective

RPO --- Data Loss --- Disaster --- Downtime --- RTO


RPO: How much a data loss are you willing to accept in case of a disaster happens?

RTO: The amount of downtime that your applications have

### Disaster Recovery Strategies

- Backup and restore
- Pilot Light
- Warm Standby
- Hot Site/ Multi Site Approach
 ---
   **Faster RTO**
-------------------------------->
Backup&   |  Pilot    Warm     Multi
Restore   |  Light    Standby  Site

------- AWS Multi Region------

- Backup and Restore(Hight RPO)
  - recreate infrastructure when we needed
  - cheap
 
- Pilot Light
  - A small version of the app is always running in the cloud
  - Useful for the critical core(pilot light)
  - Very similar to Backup and Restore
  - Faster than Backup and Restore as critical systems are already up

- Warm Stadnby
  - Full system is up and running, but at minimum size
  - Upon Disaster, we can scale to production load
  
- Multi Site / Hot Site Approach
  - Very low RTO(minutes or seconds) - very expensive
  - Full Production Scale is running AWS and On Premise-

- All AWS Multi Region

### Disaster Recovery Tips

- Backup
   - EBS Snapshots, RDS automated backups / Snapshots, etc......
   - Regular pushes to S3/ S3 IA/ Glacier, Lifecycle Policy, Cross Region Replication
 
- High Avaliability
  - Use Route53 to migrate DNS over from Region to Region
  - RDS Multi-AZ ElasticCache Multi-AZ, EFS, S3
  - Site to Site VPN as a recovery from Direct Connect
  -
- Replication 
  - RDS Replication(Cross Region), AWS Aurora + Global Databases
  - Databases replication from on-premise to RDS
  - Storage Gateway
- Automation
  - Cloudformation /Elastic Beanstalk to re-create a whole nes environment
  - Recover /Reboot Ec2 instances with CloudWatch if alarms fail
  - AWS Lambda functions fot customized automations

- Chaos
  - Netflix has a "simian-army" randomly terminate EC2



## VPC
VPC Basics:
- CIDR : Block of IP address 
  - e.g. 192.168.0.0/26(共32-26=6 2的6次方個ip) : 192.168.0.0 - 192.168.0.63(64ip)
  - Used for security group, route tables, vpc, subnets, etc....

- Private IP:
   - 10.0.0.0 - 10.255.255.255(10.0.0.0/8) <= in big networks
   - 172.16.0.0 - 172.31.255.255(172.16.0.0/12) <= default AWS Zone
   - 192.168.0.0 - 192.168.255.255(192.168.0.0/16) <= example home networks

- Public Ip(the rest)

- VPC
   - A VPC must have a defined list of CIDR blocks, that cannot be changed.
   - Each CIDR within VPC: min size is /28, max size is /16(65536ip)
   - VPC is private, so only private ip CIDR ranges are allowed
  
- Subnets
   - Within a VPC, defined as a CIDR that is a subnet the VPC CIDR
   - All instances within subnet get a private IP
   - First 4 IP and last one in every subnet is reserved by AWS

- Route Table
   - Used to control where the network traffic is directed to
   - Can be associated with specific subnets
   - The most specifuc rooitng route is always followed(192.168.0.0/24 beats 0.0.0.0/0)


- Internet Gateway (IGW)
  - Helps our VPC connect to the internet, HA, scales horizontally
  - Acts as NAT for instances that have a public IPV4 or public IPV6
  
- Public Subnets
  - Has a route table that sends 0.0.0.0/0 to an IGW
  - Instance must have a public IPV4 to talk to the internet

- Private Subnets
  - Access Internet with a NAT instance or NAT Gateway set up in public subnet(but 2021 you don't have to )
  - Must edit routes so that 0.0.0.0/0 route traffic to NAT


- NAT Instance
  - EC2 instance you deploy in public subnet
  - Edit the route in your private subnet to route 0.0.0.0/0 to your NAT instance.
  - Not resiliet to failure, limited bandwidth based on instance type, cheap
  - Must manage failover yourself

- NAT Gateway
  - Managed NAT Solutions, bandwidth scales automatically
  - Resilient to failure within a single AZ
  - Must deploy multiple NAT gateway in Multiple AZ for HA
  - Has an Elastic IP, external services see the ip for the NAT Gateway as the source.

- Networks ACL(NACL)
  - Stateless firewall defined at the subnet level, applies to all instance within
  - Support for allow and deny rules
  - Stateless = return traffic must be explicity allowed by rules
  - Helpful to quickly & cheaply block specific IP addresses.

- Security Groups
  - Applied at the instance level, only support for allow rule, no deny rules.
  - Stateful = return traffic is automatically allowed, regardless of rules.
  - Can reference other security groups in the same region(peered VPC, cross-account)

- VPC flow logs
  -  Log internet traffic going through your VPC
  -  Can be defined at the VPC level, subnet level , ENI-level
  -  Helpful to capture "defined internet traffic".
  -  Can be sent to Cloudwatch Logs and AWS S3
 
- Bastion Hosts
  - SSH into private EC2 instances through a public EC2 instance.
  - You must manage these instances yourself(failover, recovery)
  - SSM Session Manager is a secure way to remote control withouth SSH.

-  IPV6 is short
   -  All IPV6 address are public, total 3.4x10＾38 address(v.s 4.3 billion IPV4)
   -  Example CIDR: 2600:ifi8:80C:a900::/56
   -  Addresses are "random" and can't be scarred online(too many)
- VPC support for IPV6
  - Create an IPV6 CIDR for VPC & use an IGW(support IPV6)
  - Public subnet:
     - Create an instance with IPV6 support
     - Create route table entry to ::/0
- private subnet: 
  - Create an engress-only IGW in the public subnet
  - Add route table entry for the private subnet from ::/0 to the Egress-Only IGW.

- VPC endpoint
  - Interface Endpoint are Elastic Network Interface(ENI) with private IP address -> power by AWS PrivateLink
  - A Gateway Endpoints is a gateway that is a target for a specific route in your route table, used for traffic destined for a supported AWS service. only S3 and dynamodb.


### Different between VPC Peering and Transit Gateway.

https://www.linkedin.com/pulse/what-transit-gateway-vpc-peering-difference-between-them-kumar/

## Other Services

### other Services

### CICD

### Cloudsearch

### Alexa for Business, Lex & Connect


### AWS Rekognition

### Kinesis Video Streams

### AWS Workspaces and Amazon AppStream2.0

### Amazon Mechanical Turk

### AWS Device Farm








## Exam Preparation











## 專有名詞特區

### What is CDC?(不是美國疾病管制與預防中心歐)
Change data capture(CDC)tracks change in a source dataset and automatically transfer those changes to a target database.

### What is TDE?
Transparent Data Encryption(often abbreviated to TDE)is a technology employed by Microsoft, IBM and Oracle to encypt database files.

### Why We need external ID? Cuz Confused Deputy
In information security, the confused deputy problem is often cited as an example of why capability-based security is important. A confused deputy is a legitimate, more privileged computer program that is tricked by another program into misusing its authority on the system. It is a specific type of privilege escalation.


### Principle of least privilege
In information security, computer science, and other fields, the principle of least privilege (PoLP), also known as the principle of minimal privilege or the principle of least authority, requires that in a particular abstraction layer of a computing environment, every module (such as a process, a user, or a program, depending on the subject) must be able to access only the information and resources that are necessary for its legitimate purpose.

### AD-Compatibel API: Samba
Samba，是種用來讓UNIX系列的作業系統與微軟Windows作業系統的SMB/CIFS（Server Message Block/Common Internet File System）網路協定做連結的自由軟體。第三版不僅可存取及分享SMB的資料夾及印表機，本身還可以整合入Windows Server的網域，扮演為網域控制站（Domain Controller）以及加入Active Directory成員。簡而言之，此軟體在Windows與UNIX系列操作系统之間搭起一座橋樑，讓兩者的資源可互通有無

### What is an identity provider (IdP)?
An identity provider (IdP or IDP) stores and manages users' digital identities. Think of an IdP as being like a guest list, but for digital and cloud-hosted applications instead of an event. An IdP may check user identities via username-password combinations and other factors, or it may simply provide a list of user identities that another service provider (like an SSO) checks.
IdPs are not limited to verifying human users. Technically, an IdP can authenticate any entity connected to a network or a system, including computers and other devices. Any entity stored by an IdP is known as a "principal" (instead of a "user"). However, IdPs are most often used in cloud computing to manage user identities.

### What is WORM(Write once Read Many) model?
1. S3 object lock
2. Glacier Vault lock

### CORS
跨來源資源共用（Cross-Origin Resource Sharing (CORS)）是一種使用額外 HTTP 標頭令目前瀏覽網站的使用者代理 (en-US)取得存取其他來源（網域）伺服器特定資源權限的機制。當使用者代理請求一個不是目前文件來源——例如來自於不同網域（domain）、通訊協定（protocol）或通訊埠（port）的資源時，會建立一個跨來源 HTTP 請求（cross-origin HTTP request）。

舉個跨來源請求的例子：http://domain-a.com HTML 頁面裡面一個 <img> 標籤的 src 屬性 (en-US)載入來自 http://domain-b.com/image.jpg 的圖片。現今網路上許多頁面所載入的資源，如 CSS 樣式表、圖片影像、以及指令碼（script）都來自與所在位置分離的網域，如內容傳遞網路（content delivery networks, CDN）。

基於安全性考量，程式碼所發出的跨來源 HTTP 請求會受到限制。例如，XMLHttpRequest 及 Fetch 都遵守同源政策（same-origin policy）。這代表網路應用程式所使用的 API 除非使用 CORS 標頭，否則只能請求與應用程式相同網域的 HTTP 資源。

### What are Cookies?

HTTP cookies are essential to the modern Internet but a vulnerability to your privacy. As a necessary part of web browsing, HTTP cookies help web developers give you more personal, convenient website visits. Cookies let websites remember you, your website logins, shopping carts and more. But they can also be a treasure trove of private info for criminals to spy on.



### Web Indexing
Web indexing, or internet indexing, comprises methods for indexing the contents of a website or of the Internet as a whole. Individual websites or intranets may use a back-of-the-book index, while search engines usually use keywords and metadata to provide a more useful vocabulary for Internet or onsite searching. With the increase in the number of periodicals that have articles online, web indexing is also becoming important for periodical websites.

### What is cron job?
我們通常會把一些每小時、每 6 小時、每日、每週、每月等等之類固定時間要做的工作丟到 Linux 系統的 crontab 中去執行，通常像是每日要統計昨天網站的活動資訊做數據分析之類的工作，這類的工作通常會花費比較久的時間

若是事件驅動的行為，需要花比較多時間執行的話，我們會使用 Queue 的方式做處理，讓網站的回應時間變快，花時間的工作背景處理

像是會員使用 Email 當作帳號註冊後，需要發送 Email 確認信給會員，以便確認這個 Email 真的存在

但是因為這樣寄送 Email 的時間是不確定的時間（我們沒辦法控制使用者什麼時候來註冊）

而且寄送 Email 的執行時間又特別的長，所以只能用 Queue 的方式來處理

### What is Lazy Loading?
Lazy loading (also called on-demand loading) is an optimization technique for the online content, be it a website or a web app.
Instead of loading the entire web page and rendering it to the user in one go as in bulk loading, the concept of lazy loading assists in loading only the required section and delays the remaining, until it is needed by the user.

### Compilance- What is HIPPA and HITECT?
美國 1996 年健康保險流通與責任法案 (HIPAA) 法規的目的在於讓美國勞工在轉換工作或失業時更容易保留健康保險。法規的另一個目的是鼓勵採用電子健康記錄，透過改善資訊共享提升美國健保系統的效率和品質。

隨著電子病歷使用的增加，HIPAA 也包含對受保護的醫療資訊 (PHI) 安全和隱私提供保護的規定。PHI 包含各式各樣的個人識別健康資料以及和健康相關的資料，包括保險和帳單資訊、診斷資料、臨床護理資料，及影像等實驗室結果和測試結果。HIPAA 法規適用的涵蓋實體包含直接處理病患和病患資料的醫院、醫療服務提供者、雇主贊助的醫療計劃、研究機構和保險公司。HIPAA 保護 PHI 的要求也擴及商業夥伴。

經濟與臨床健康資訊科技法 (HITECH) 於 2009 擴大了 HIPAA 法規的範圍。HIPAA 和 HITECH 共同建立了一套聯邦標準，旨在保護 PHI 的安全和隱私。這些規定包含在稱為「簡化管理」的規則中。HIPAA 和 HITECH 強制推行使用和公開 PHI 的相關需求、保護 PHI 的適當安全措施、個人權利和管理責任。

如需 HIPAA 和 HITECH 如何保護醫療資訊的詳細資訊，請參閱美國衛生與公眾服務部門的 Health Information Privacy 網頁。

### What is Kerberos?
Kerberos was designed to provide secure authentication to services over an insecure network. Kerberos uses tickets to authenticate a user and completely avoids sending passwords across the network. 

### DEFINITION OF DATA IN TRANSIT VS. DATA AT REST
Data in transit, or data in motion, is data actively moving from one location to another such as across the internet or through a private network. Data protection in transit is the protection of this data while it’s traveling from network to network or being transferred from a local storage device to a cloud storage device – wherever data is moving, effective data protection measures for in transit data are critical as data is often considered less secure while in motion.

Data at rest is data that is not actively moving from device to device or network to network such as data stored on a hard drive, laptop, flash drive, or archived/stored in some other way. Data protection at rest aims to secure inactive data stored on any device or network. While data at rest is sometimes considered to be less vulnerable than data in transit, attackers often find data at rest a more valuable target than data in motion. The risk profile for data in transit or data at rest depends on the security measures that are in place to secure data in either state.

### SSO with ADFS
https://www.cc.ntu.edu.tw/chinese/epaper/0025/20130620_2509.html

### What is Microsoft AD?

### What is iSCSI?
In computing, iSCSI is an acronym for Internet Small Computer Systems Interface, an Internet Protocol (IP)-based storage networking standard for linking data storage facilities

### What is Envelope Encyption?
Envelope encryption
When you encrypt your data, your data is protected, but you have to protect your encryption key. One strategy is to encrypt it. Envelope encryption is the practice of encrypting plaintext data with a data key, and then encrypting the data key under another key.

You can even encrypt the data encryption key under another encryption key, and encrypt that encryption key under another encryption key. But, eventually, one key must remain in plaintext so you can decrypt the keys and your data. This top-level plaintext key encryption key is known as the master key.

### 3 ELB details
However, Classic Load Balancers and Application Load Balancers use the private IP addresses associated with their elastic network interfaces as the source IP address for requests forwarded to your web servers. For Network Load Balancers, the source IP address of these requests depends on the configuration of its target group.

These IP addresses can be used for various purposes, such as allowing the load balancer traffic on the web servers and for request processing. It's a best practice to use security group referencing on the web server's security group inbound rules for allowing load balancer traffic from Classic Load Balancers or Application Load Balancers. However, because Network Load Balancers don't support security groups, based on the target group configurations, the IP addresses of the clients or the private IP addresses associated with the Network Load Balancers must be allowed on the web server's security group.

### POSIX

可移植作業系統介面（英語：Portable Operating System Interface，縮寫為POSIX）是IEEE為要在各種UNIX作業系統上執行軟體，而定義API的一系列互相關聯的標準的總稱，其正式稱呼為IEEE Std 1003，而國際標準名稱為ISO/IEC 9945。此標準源於一個大約開始於1985年的專案。POSIX這個名稱是由理察·斯托曼（RMS）應IEEE的要求而提議的一個易於記憶的名稱。它基本上是Portable Operating System Interface（可移植作業系統介面）的縮寫，而X則表明其對Unix API的傳承。

Linux基本上逐步實現了POSIX相容，但並沒有參加正式的POSIX認證。[1]

微軟的Windows NT聲稱部分實現了POSIX標準。

當前的POSIX主要分為四個部分[2]：Base Definitions、System Interfaces、Shell and Utilities和Rationale。

### 反向代理

在電腦網路中是代理伺服器的一種。伺服器根據客戶端的請求，從其關聯的一組或多組後端伺服器（如Web伺服器）上取得資源，然後再將這些資源返回給客戶端，客戶端只會得知反向代理的IP位址，而不知道在代理伺服器後面的伺服器叢集的存在[1]。

與前向代理不同，前向代理作為客戶端的代理，將從網際網路上取得的資源返回給一個或多個的客戶端，伺服器端（如Web伺服器）只知道代理的IP位址而不知道客戶端的IP位址；而反向代理是作為伺服器端（如Web伺服器）的代理使用，而不是客戶端。客戶端藉由前向代理可以間接存取很多不同網際網路伺服器（叢集）的資源，而反向代理是供很多客戶端都通過它間接存取不同後端伺服器上的資源，而不需要知道這些後端伺服器的存在，而以為所有資源都來自於這個反向代理伺服器。

反向代理在現時的網際網路中並不少見，而另一些例子，像是CDN、SNI代理等，是反向代理結合DNS的一類延伸應用。

### What is Blobs-
二進位大型物件（英語：binary large object ，或英語：basic large object，縮寫為Blob、BLOB、BLOb），在資料庫管理系統中，將二進位資料儲存為一個單一個體的集合。Blob通常是影像、聲音或多媒體檔案。

它由迪吉多公司的工程師吉姆·史塔基（Jim Starkey）發明。

### Dependency Mapping
Businesses today have several applications dependent on different servers and separate network devices. Application dependency mapping is the process of figuring out which applications are dependent on what, in the context of your entire network infrastructure. Following application discovery, dependency mapping looks at what applications you’ve installed on your devices, and then looks at how these applications are interconnected.

