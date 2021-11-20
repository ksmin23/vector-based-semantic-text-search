#!/usr/bin/env python3
import os
import json
import random
import string

from aws_cdk import (
  core as cdk,
  aws_ec2,
  aws_iam,
  aws_opensearchservice,
  aws_s3 as s3,
  aws_sagemaker,
  aws_secretsmanager
)

random.seed(47)

class VectorBasedSemanticSearchStack(cdk.Stack):

  def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    OPENSEARCH_DOMAIN_NAME = cdk.CfnParameter(self, 'OpenSearchDomainName',
      type='String',
      description='Amazon OpenSearch Service domain name',
      default='opensearch-{}'.format(''.join(random.sample((string.ascii_letters), k=5))),
      allowed_pattern='[a-z]+[A-Za-z0-9\-]+'
    )

    EC2_KEY_PAIR_NAME = cdk.CfnParameter(self, 'EC2KeyPairName',
      type='String',
      description='Amazon EC2 Instance KeyPair name'
    )

    SAGEMAKER_NOTEBOOK_INSTANCE_TYPE = cdk.CfnParameter(self, 'SageMakerNotebookInstanceType',
      type='String',
      description='Amazon SageMaker Notebook instance type',
      default='ml.t2.medium'
    )

    #XXX: For createing Amazon MWAA in the existing VPC,
    # remove comments from the below codes and
    # comments out vpc = aws_ec2.Vpc(..) codes,
    # then pass -c vpc_name=your-existing-vpc to cdk command
    # for example,
    # cdk -c vpc_name=your-existing-vpc syth
    #
    vpc_name = self.node.try_get_context('vpc_name')
    vpc = aws_ec2.Vpc.from_lookup(self, 'ExistingVPC',
      is_default=True,
      vpc_name=vpc_name
    )

    # vpc = aws_ec2.Vpc(self, "OpenSearchVPC",
    #   max_azs=3,
    #   gateway_endpoints={
    #     "S3": aws_ec2.GatewayVpcEndpointOptions(
    #       service=aws_ec2.GatewayVpcEndpointAwsService.S3
    #     )
    #   }
    # )

    #XXX: https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_ec2/InstanceClass.html
    #XXX: https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_ec2/InstanceSize.html#aws_cdk.aws_ec2.InstanceSize
    ec2_instance_type = aws_ec2.InstanceType.of(aws_ec2.InstanceClass.BURSTABLE3, aws_ec2.InstanceSize.MEDIUM)

    sg_bastion_host = aws_ec2.SecurityGroup(self, "BastionHostSG",
      vpc=vpc,
      allow_all_outbound=True,
      description='security group for an bastion host',
      security_group_name='bastion-host-{}-sg'.format(''.join(random.sample((string.ascii_letters), k=5)))
    )
    cdk.Tags.of(sg_bastion_host).add('Name', 'bastion-host-sg')

    #TODO: SHOULD restrict IP range allowed to ssh acces
    sg_bastion_host.add_ingress_rule(peer=aws_ec2.Peer.ipv4("0.0.0.0/0"), connection=aws_ec2.Port.tcp(22), description='SSH access')

    bastion_host = aws_ec2.Instance(self, "BastionHost",
      vpc=vpc,
      instance_type=ec2_instance_type,
      machine_image=aws_ec2.MachineImage.latest_amazon_linux(),
      vpc_subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PUBLIC),
      security_group=sg_bastion_host,
      key_name=EC2_KEY_PAIR_NAME.value_as_string
    )

    sg_use_opensearch = aws_ec2.SecurityGroup(self, "OpenSearchClientSG",
      vpc=vpc,
      allow_all_outbound=True,
      description='security group for an opensearch client',
      security_group_name='use-opensearch-cluster-{}-sg'.format(''.join(random.sample((string.ascii_letters), k=5)))
    )
    cdk.Tags.of(sg_use_opensearch).add('Name', 'use-opensearch-cluster-sg')

    sg_opensearch_cluster = aws_ec2.SecurityGroup(self, "OpenSearchSG",
      vpc=vpc,
      allow_all_outbound=True,
      description='security group for an opensearch cluster',
      security_group_name='opensearch-cluster-{}-sg'.format(''.join(random.sample((string.ascii_letters), k=5)))
    )
    cdk.Tags.of(sg_opensearch_cluster).add('Name', 'opensearch-cluster-sg')

    sg_opensearch_cluster.add_ingress_rule(peer=sg_opensearch_cluster, connection=aws_ec2.Port.all_tcp(), description='opensearch-cluster-sg')

    sg_opensearch_cluster.add_ingress_rule(peer=sg_use_opensearch, connection=aws_ec2.Port.tcp(443), description='use-opensearch-cluster-sg')
    sg_opensearch_cluster.add_ingress_rule(peer=sg_use_opensearch, connection=aws_ec2.Port.tcp_range(9200, 9300), description='use-opensearch-cluster-sg')

    sg_opensearch_cluster.add_ingress_rule(peer=sg_bastion_host, connection=aws_ec2.Port.tcp(443), description='bastion-host-sg')
    sg_opensearch_cluster.add_ingress_rule(peer=sg_bastion_host, connection=aws_ec2.Port.tcp_range(9200, 9300), description='bastion-host-sg')

    master_user_secret = aws_secretsmanager.Secret(self, "OpenSearchMasterUserSecret",
      generate_secret_string=aws_secretsmanager.SecretStringGenerator(
        secret_string_template=json.dumps({"username": "admin"}),
        generate_string_key="password",
        # Master password must be at least 8 characters long and contain at least one uppercase letter,
        # one lowercase letter, one number, and one special character.
        password_length=8
      )
    )

    #XXX: aws cdk elastsearch example - https://github.com/aws/aws-cdk/issues/2873
    # You should camelCase the property names instead of PascalCase
    opensearch_domain = aws_opensearchservice.Domain(self, "OpenSearch",
      domain_name=OPENSEARCH_DOMAIN_NAME.value_as_string,
      version=aws_opensearchservice.EngineVersion.OPENSEARCH_1_0,
      capacity={
        "master_nodes": 3,
        "master_node_instance_type": "r6g.large.search",
        "data_nodes": 3,
        "data_node_instance_type": "r6g.large.search"
      },
      ebs={
        "volume_size": 10,
        "volume_type": aws_ec2.EbsDeviceVolumeType.GP2
      },
      #XXX: az_count must be equal to vpc subnets count.
      zone_awareness={
        "availability_zone_count": 3
      },
      logging={
        "slow_search_log_enabled": True,
        "app_log_enabled": True,
        "slow_index_log_enabled": True
      },
      fine_grained_access_control=aws_opensearchservice.AdvancedSecurityOptions(
        master_user_name=master_user_secret.secret_value_from_json("username").to_string(),
        master_user_password=master_user_secret.secret_value_from_json("password")
      ),
      # Enforce HTTPS is required when fine-grained access control is enabled.
      enforce_https=True,
      # Node-to-node encryption is required when fine-grained access control is enabled
      node_to_node_encryption=True,
      # Encryption-at-rest is required when fine-grained access control is enabled.
      encryption_at_rest={
        "enabled": True
      },
      use_unsigned_basic_auth=True,
      security_groups=[sg_opensearch_cluster],
      automated_snapshot_start_hour=17, # 2 AM (GTM+9)
      vpc=vpc,
      vpc_subnets=[aws_ec2.SubnetSelection(one_per_az=True, subnet_type=aws_ec2.SubnetType.PRIVATE)],
      removal_policy=cdk.RemovalPolicy.DESTROY # default: cdk.RemovalPolicy.RETAIN
    )
    cdk.Tags.of(opensearch_domain).add('Name', f'{OPENSEARCH_DOMAIN_NAME.value_as_string}')

    sg_sagemaker_notebook_instance = aws_ec2.SecurityGroup(self, "SageMakerNotebookSG",
      vpc=vpc,
      allow_all_outbound=True,
      description='Security group with no ingress rule',
      security_group_name='sagemaker-nb-{}-sg'.format(''.join(random.sample((string.ascii_letters), k=5)))
    )
    sg_sagemaker_notebook_instance.add_ingress_rule(peer=sg_sagemaker_notebook_instance, connection=aws_ec2.Port.all_traffic(), 
      description='sagemaker notebook security group')
    cdk.Tags.of(sg_sagemaker_notebook_instance).add('Name', 'sagemaker-nb-sg')

    sagemaker_notebook_role_policy_doc = aws_iam.PolicyDocument()
    sagemaker_notebook_role_policy_doc.add_statements(aws_iam.PolicyStatement(**{
      "effect": aws_iam.Effect.ALLOW,
      "resources": ["arn:aws:s3:::*"],
      "actions": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
    ]}))

    sagemaker_notebook_role_policy_doc.add_statements(aws_iam.PolicyStatement(**{
      "effect": aws_iam.Effect.ALLOW,
      "resources": [master_user_secret.secret_full_arn],
      "actions": [
        "secretsmanager:GetRandomPassword",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:ListSecretVersionIds",
        "secretsmanager:ListSecrets"
      ]}))

    sagemaker_notebook_role = aws_iam.Role(self, 'SageMakerNotebookRole',
      role_name='SageMakerNotebookRole-{suffix}'.format(suffix=''.join(random.sample((string.ascii_letters), k=5))),
      assumed_by=aws_iam.ServicePrincipal('sagemaker.amazonaws.com'),
      inline_policies={
        'sagemaker-custome-execution-role': sagemaker_notebook_role_policy_doc
      },
      managed_policies=[
        aws_iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSageMakerFullAccess'),
        aws_iam.ManagedPolicy.from_aws_managed_policy_name('AWSCloudFormationReadOnlyAccess')
      ]
    )

    #XXX: skip downloading rds-combined-ca-bundle.pem if not use SSL with a MySQL DB instance
    # https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_MySQL.html#MySQL.Concepts.SSLSupport
    sagemaker_nb_lifecycle_content = '''#!/bin/bash
sudo -u ec2-user -i <<'EOF'

echo "export AWS_REGION={AWS_Region}" >> ~/.bashrc

for each in tensorflow2_p36 tensorflow_p36
do
  source /home/ec2-user/anaconda3/bin/activate ${{each}}
  pip install tensorflow-hub
  pip install 'elasticsearch < 7.14'
  pip install requests
  pip install requests-aws4auth
  conda deactivate
done
EOF
'''.format(AWS_Region=cdk.Aws.REGION)

    sagemaker_lifecycle_config_prop = aws_sagemaker.CfnNotebookInstanceLifecycleConfig.NotebookInstanceLifecycleHookProperty(
      content=cdk.Fn.base64(sagemaker_nb_lifecycle_content)
    )

    sagemaker_lifecycle_config = aws_sagemaker.CfnNotebookInstanceLifecycleConfig(self, 'SageMakerNotebookLifeCycleConfig',
      notebook_instance_lifecycle_config_name='SageMakerNotebookLifeCycleConfig',
      on_start=[sagemaker_lifecycle_config_prop]
    )

    sagemaker_notebook_instance = aws_sagemaker.CfnNotebookInstance(self, 'SageMakerNotebookInstance',
      instance_type=SAGEMAKER_NOTEBOOK_INSTANCE_TYPE.value_as_string,
      role_arn=sagemaker_notebook_role.role_arn,
      lifecycle_config_name=sagemaker_lifecycle_config.notebook_instance_lifecycle_config_name,
      notebook_instance_name='MySageMakerWorkbook',
      root_access='Disabled',
      security_group_ids=[sg_sagemaker_notebook_instance.security_group_id, sg_use_opensearch.security_group_id],
      subnet_id=vpc.select_subnets(subnet_type=aws_ec2.SubnetType.PRIVATE).subnet_ids[0]
    )

    cdk.CfnOutput(self, 'BastionHostId', value=bastion_host.instance_id)
    cdk.CfnOutput(self, 'BastionHostPublicDnsName', value=bastion_host.instance_public_dns_name)
    cdk.CfnOutput(self, 'BastionHostPublicIP', value=bastion_host.instance_public_ip)
    cdk.CfnOutput(self, 'OpenSearchDomainEndpoint', value=opensearch_domain.domain_endpoint)
    cdk.CfnOutput(self, 'OpenSearchDashboardsURL', value=f"{opensearch_domain.domain_endpoint}/_dashboards/")
    cdk.CfnOutput(self, 'MasterUserSecretId', value=master_user_secret.secret_name)
    cdk.CfnOutput(self, 'SageMakerNotebookURL', 
      value='https://console.aws.amazon.com/sagemaker/home?region={AWS_Region}#/notebook-instances/openNotebook/{NotebookInstanceName}?view=lab'.format(
        AWS_Region=cdk.Aws.REGION,
        NotebookInstanceName=sagemaker_notebook_instance.notebook_instance_name))


app = cdk.App()
VectorBasedSemanticSearchStack(app, "VectorBasedSemanticSearchStack",
  env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'),
    region=os.getenv('CDK_DEFAULT_REGION')))

app.synth()
