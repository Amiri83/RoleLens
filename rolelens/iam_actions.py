"""A built-in catalog of IAM action names for the editor's validation.

Not exhaustive: it covers the services roles use most. An action of a service listed
here must match a known action (wildcards included) or validation reports an error; an
action of a service that is not listed only gets a warning ("not checked"). Matching is
case-insensitive, like IAM.
"""

from __future__ import annotations

import fnmatch
from functools import cache


def _names(text: str) -> frozenset[str]:
    return frozenset(text.split())


CATALOG: dict[str, frozenset[str]] = {
    "s3": _names(
        """
        AbortMultipartUpload CreateBucket DeleteBucket DeleteBucketPolicy DeleteObject
        DeleteObjectTagging DeleteObjectVersion GetBucketAcl GetBucketCORS GetBucketLocation
        GetBucketLogging GetBucketNotification GetBucketPolicy GetBucketPolicyStatus
        GetBucketPublicAccessBlock GetBucketTagging GetBucketVersioning GetBucketWebsite
        GetEncryptionConfiguration GetLifecycleConfiguration GetObject GetObjectAcl
        GetObjectAttributes GetObjectTagging GetObjectVersion GetReplicationConfiguration
        ListAllMyBuckets ListBucket ListBucketMultipartUploads ListBucketVersions
        ListMultipartUploadParts PutBucketAcl PutBucketCORS PutBucketLogging
        PutBucketNotification PutBucketPolicy PutBucketPublicAccessBlock PutBucketTagging
        PutBucketVersioning PutEncryptionConfiguration PutLifecycleConfiguration PutObject
        PutObjectAcl PutObjectTagging ReplicateObject RestoreObject
        """
    ),
    "ec2": _names(
        """
        AssignPrivateIpAddresses AttachVolume AuthorizeSecurityGroupEgress
        AuthorizeSecurityGroupIngress CreateNetworkInterface CreateSecurityGroup CreateSnapshot
        CreateTags CreateVolume DeleteNetworkInterface DeleteSecurityGroup DeleteSnapshot
        DeleteTags DeleteVolume DescribeAvailabilityZones DescribeImages DescribeInstances
        DescribeInstanceStatus DescribeNetworkInterfaces DescribeRegions DescribeRouteTables
        DescribeSecurityGroups DescribeSnapshots DescribeSubnets DescribeTags DescribeVolumes
        DescribeVpcEndpoints DescribeVpcs DetachVolume ModifyInstanceAttribute RebootInstances
        RevokeSecurityGroupEgress RevokeSecurityGroupIngress RunInstances StartInstances
        StopInstances TerminateInstances UnassignPrivateIpAddresses
        """
    ),
    "iam": _names(
        """
        AttachRolePolicy CreatePolicy CreatePolicyVersion CreateRole CreateServiceLinkedRole
        DeletePolicy DeleteRole DeleteRolePolicy DetachRolePolicy GetAccountSummary GetPolicy
        GetPolicyVersion GetRole GetRolePolicy GetUser ListAccountAliases
        ListAttachedRolePolicies ListPolicies ListPolicyVersions ListRolePolicies ListRoles
        ListRoleTags ListUsers PassRole PutRolePolicy SimulatePrincipalPolicy TagRole UntagRole
        UpdateAssumeRolePolicy UpdateRole
        """
    ),
    "sts": _names(
        """
        AssumeRole AssumeRoleWithSAML AssumeRoleWithWebIdentity DecodeAuthorizationMessage
        GetAccessKeyInfo GetCallerIdentity GetFederationToken GetSessionToken SetContext
        SetSourceIdentity TagSession
        """
    ),
    "lambda": _names(
        """
        AddPermission CreateEventSourceMapping CreateFunction DeleteEventSourceMapping
        DeleteFunction GetFunction GetFunctionConfiguration GetLayerVersion GetPolicy
        InvokeFunction InvokeFunctionUrl ListAliases ListEventSourceMappings ListFunctions
        ListTags ListVersionsByFunction PublishVersion RemovePermission TagResource
        UntagResource UpdateFunctionCode UpdateFunctionConfiguration
        """
    ),
    "dynamodb": _names(
        """
        BatchGetItem BatchWriteItem ConditionCheckItem CreateTable DeleteItem DeleteTable
        DescribeContinuousBackups DescribeStream DescribeTable DescribeTimeToLive GetItem
        GetRecords GetShardIterator ListStreams ListTables ListTagsOfResource PartiQLSelect
        PutItem Query Scan TagResource UntagResource UpdateItem UpdateTable
        """
    ),
    "sqs": _names(
        """
        ChangeMessageVisibility CreateQueue DeleteMessage DeleteQueue GetQueueAttributes
        GetQueueUrl ListDeadLetterSourceQueues ListQueues ListQueueTags PurgeQueue
        ReceiveMessage SendMessage SetQueueAttributes TagQueue UntagQueue
        """
    ),
    "sns": _names(
        """
        ConfirmSubscription CreateTopic DeleteTopic GetSubscriptionAttributes
        GetTopicAttributes ListSubscriptions ListSubscriptionsByTopic ListTagsForResource
        ListTopics Publish SetTopicAttributes Subscribe TagResource Unsubscribe UntagResource
        """
    ),
    "kms": _names(
        """
        CreateGrant CreateKey Decrypt DescribeKey DisableKey EnableKeyRotation Encrypt
        GenerateDataKey GenerateDataKeyPair GenerateDataKeyWithoutPlaintext GetKeyPolicy
        GetKeyRotationStatus GetPublicKey ListAliases ListGrants ListKeys ListResourceTags
        PutKeyPolicy ReEncryptFrom ReEncryptTo RetireGrant RevokeGrant ScheduleKeyDeletion
        Sign Verify
        """
    ),
    "logs": _names(
        """
        CreateLogGroup CreateLogStream DeleteLogGroup DescribeLogGroups DescribeLogStreams
        DescribeSubscriptionFilters FilterLogEvents GetLogEvents GetQueryResults
        ListTagsForResource PutLogEvents PutRetentionPolicy PutSubscriptionFilter StartQuery
        StopQuery TagResource
        """
    ),
    "cloudwatch": _names(
        """
        DeleteAlarms DescribeAlarmHistory DescribeAlarms GetDashboard GetMetricData
        GetMetricStatistics ListDashboards ListMetrics PutDashboard PutMetricAlarm
        PutMetricData
        """
    ),
    "secretsmanager": _names(
        """
        BatchGetSecretValue CreateSecret DeleteSecret DescribeSecret GetRandomPassword
        GetResourcePolicy GetSecretValue ListSecrets ListSecretVersionIds PutSecretValue
        RotateSecret TagResource UntagResource UpdateSecret
        """
    ),
    "ssm": _names(
        """
        AddTagsToResource DeleteParameter DescribeInstanceInformation DescribeParameters
        GetCommandInvocation GetParameter GetParameterHistory GetParameters
        GetParametersByPath ListCommands ListTagsForResource PutParameter SendCommand
        StartSession UpdateInstanceInformation
        """
    ),
    "ecr": _names(
        """
        BatchCheckLayerAvailability BatchDeleteImage BatchGetImage CompleteLayerUpload
        CreateRepository DeleteRepository DescribeImages DescribeRepositories
        GetAuthorizationToken GetDownloadUrlForLayer GetRepositoryPolicy InitiateLayerUpload
        ListImages ListTagsForResource PutImage SetRepositoryPolicy UploadLayerPart
        """
    ),
    "ecs": _names(
        """
        CreateCluster CreateService DeleteService DeregisterTaskDefinition DescribeClusters
        DescribeServices DescribeTaskDefinition DescribeTasks ExecuteCommand ListClusters
        ListServices ListTaskDefinitions ListTasks RegisterTaskDefinition RunTask StartTask
        StopTask TagResource UpdateService
        """
    ),
    "rds": _names(
        """
        AddTagsToResource CreateDBInstance CreateDBSnapshot DeleteDBInstance
        DescribeDBClusters DescribeDBInstances DescribeDBSnapshots DescribeDBSubnetGroups
        ListTagsForResource ModifyDBInstance RebootDBInstance StartDBInstance StopDBInstance
        """
    ),
    "states": _names(
        """
        CreateStateMachine DeleteStateMachine DescribeExecution DescribeStateMachine
        GetExecutionHistory ListExecutions ListStateMachines SendTaskFailure
        SendTaskHeartbeat SendTaskSuccess StartExecution StopExecution UpdateStateMachine
        """
    ),
    "events": _names(
        """
        DeleteRule DescribeRule DisableRule EnableRule ListRules ListTargetsByRule PutEvents
        PutRule PutTargets RemoveTargets
        """
    ),
    "kinesis": _names(
        """
        CreateStream DeleteStream DescribeStream DescribeStreamSummary GetRecords
        GetShardIterator ListShards ListStreams PutRecord PutRecords SubscribeToShard
        """
    ),
    "xray": _names(
        """
        GetSamplingRules GetSamplingStatisticSummaries GetSamplingTargets
        PutTelemetryRecords PutTraceSegments
        """
    ),
    "cloudformation": _names(
        """
        CreateChangeSet CreateStack DeleteStack DescribeChangeSet DescribeStackEvents
        DescribeStackResources DescribeStacks ExecuteChangeSet GetTemplate ListStackResources
        ListStacks UpdateStack ValidateTemplate
        """
    ),
    "tag": _names("GetResources GetTagKeys GetTagValues TagResources UntagResources"),
}

# Actions allowed in a role trust policy.
TRUST_ACTIONS = frozenset(
    {
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
        "sts:TagSession",
        "sts:SetSourceIdentity",
        "sts:SetContext",
    }
)


@cache
def _lower(service: str) -> frozenset[str]:
    return frozenset(a.lower() for a in CATALOG.get(service, ()))


def is_known_service(service: str) -> bool:
    return service.lower() in CATALOG


def matching_actions(service: str, pattern: str) -> list[str]:
    """Known actions of ``service`` matching ``pattern`` (``*`` / ``?`` wildcards)."""
    service = service.lower()
    pat = pattern.lower()
    return sorted(a for a in CATALOG.get(service, ()) if fnmatch.fnmatchcase(a.lower(), pat))


def is_known_action(service: str, name: str) -> bool:
    """True if ``service:name`` (wildcards allowed) matches at least one known action."""
    if "*" in name or "?" in name:
        return bool(matching_actions(service, name))
    return name.lower() in _lower(service.lower())
