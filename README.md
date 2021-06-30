# AWS Certified Solutions Architect Professional 佛心大補帖

## 考題配分占比
![](https://i.imgur.com/gGhpx76.png)


## 準備時間軸


<img width="745" alt="Screen Shot 2021-06-28 at 11 28 01 PM" src="https://user-images.githubusercontent.com/50194219/123662931-7d944700-d868-11eb-9f4c-19ad769aa66f.png">


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

### AWS Resource Access Manager
- When you want to share VPC with multiple account think about this service.
### AWS Single Sign on
![](https://i.imgur.com/OJnRqIu.jpg)


### Summary



---
## Security

### CloudTrail
past 90 days activity

#### KMS
Use Encrypt and Decrypt API but have to check IAM permission.
#### Parameter Store

#### Secrets Manager

#### RDS Security

#### SSL Encryption, SNI(Server Name Indication) & MITM

#### AWS Certificate Manager(Regional Service)
Integrate with Load Balancers(including the one created by EB)
Cloudfront distribution
APIs on API Gateway
#### CloudHSM(Hardware Security Module)
Managed Key by customer


#### Solution Architeture - SSL on ELB

Offload SSL to CloudHSM(SSL acceleration)
#### S3 security(4 methods you could use)
SSE-S3

SSE-KMS

SSE-C(your own encryption keys)

Client Side Encyption 

Glacier: all data is AES-256 encrypted, key under AWS control


#### Network Security, DDOS, Shield & WAF

#### Blocking an IP address
ALB have security group as well
NLB didn't have security group 
If you use Cloudfront to route your internet, NACL is not useful
because cloudfront is outside of VPC! So you could use WAF or Geo-Restriction to restrict it.



#### AWS Shield 


#### AWS WAF(is not protect DDOS attack)

#### AWS Firewall Manager 


#### AWS Inspector(finished)

#### AWS Config(finished)

#### AWS Managed Logs(finished)

#### AWS GuardDuty(finished)



---

## Compute & Load Balancing

### Solutions Architeture on AWS
![](https://i.imgur.com/VdxOZjf.jpg)


### EC2
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


### Auto Scaling

### Auto Scaling Update Strategies

### Spot Instance & Spot Fleet 

### ECS- Elastic Container Service


### AWS Lambda part1

### AWS Lambda part2

### Elastic Load Balancer

### API Gateway


### Route53 part1

### Route53 part2

### Comparison of Solutions Architecture
---
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


## Service Communication

### Step Functions


### SWF


### SQS 


### Amazon MQ


### SNS


## Data Engineering


## Monitoring

## CloudWatch



## Deploy and instance Management


## Cost Control




## Migration 


### Storage Gateway



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



### Disaster Recovery
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



## Other Services







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
