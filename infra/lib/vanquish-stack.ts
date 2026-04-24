import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export class VanquishStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ── VPC ────────────────────────────────────────────────────────────────
    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: 1,
      subnetConfiguration: [
        { cidrMask: 24, name: 'Public', subnetType: ec2.SubnetType.PUBLIC },
        { cidrMask: 24, name: 'Private', subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      ],
    });

    // ── RDS PostgreSQL ─────────────────────────────────────────────────────
    const dbCredentials = rds.Credentials.fromGeneratedSecret('postgres', {
      secretName: 'vanquish/db-credentials',
    });

    const database = new rds.DatabaseInstance(this, 'Database', {
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.VER_15,
      }),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      credentials: dbCredentials,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      databaseName: 'vanquish',
      allocatedStorage: 20,
      storageType: rds.StorageType.GP2,
      backupRetention: cdk.Duration.days(7),
      deletionProtection: false,
      removalPolicy: cdk.RemovalPolicy.SNAPSHOT,
      multiAz: false,
    });

    // ── NIST API Key Secret ────────────────────────────────────────────────
    // After deploy, set the value with:
    //   aws secretsmanager put-secret-value --secret-id vanquish/nist-api-key --secret-string '{"NIST_KEY":"<your-key>"}'
    const nistSecret = new secretsmanager.Secret(this, 'NistSecret', {
      secretName: 'vanquish/nist-api-key',
      description: 'NIST NVD API key for CVSS lookups',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ NIST_KEY: 'REPLACE_ME' }),
        generateStringKey: '_unused',
      },
    });

    // ── ECR Repositories ──────────────────────────────────────────────────
    const serverRepo = new ecr.Repository(this, 'ServerRepo', {
      repositoryName: 'vanquish-server',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      imageScanOnPush: true,
      lifecycleRules: [{ maxImageCount: 10 }],
    });

    const clientRepo = new ecr.Repository(this, 'ClientRepo', {
      repositoryName: 'vanquish-client',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      imageScanOnPush: true,
      lifecycleRules: [{ maxImageCount: 10 }],
    });

    // ── ECS Cluster ────────────────────────────────────────────────────────
    const cluster = new ecs.Cluster(this, 'Cluster', {
      vpc,
      clusterName: 'vanquish',
      containerInsights: true,
    });

    // ── IAM: Task Execution Role ───────────────────────────────────────────
    const executionRole = new iam.Role(this, 'EcsExecutionRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'),
      ],
    });

    database.secret?.grantRead(executionRole);
    nistSecret.grantRead(executionRole);

    // ── Server Task Definition ─────────────────────────────────────────────
    const serverTaskDef = new ecs.FargateTaskDefinition(this, 'ServerTaskDef', {
      cpu: 256,
      memoryLimitMiB: 512,
      executionRole,
    });

    serverTaskDef.addContainer('server', {
      image: ecs.ContainerImage.fromEcrRepository(serverRepo, 'latest'),
      portMappings: [{ containerPort: 4000 }],
      environment: {
        PORT: '4000',
        NODE_ENV: 'production',
      },
      secrets: {
        DB_USER: ecs.Secret.fromSecretsManager(database.secret!, 'username'),
        DB_PASSWORD: ecs.Secret.fromSecretsManager(database.secret!, 'password'),
        DB_HOST: ecs.Secret.fromSecretsManager(database.secret!, 'host'),
        DB_PORT: ecs.Secret.fromSecretsManager(database.secret!, 'port'),
        DB_NAME: ecs.Secret.fromSecretsManager(database.secret!, 'dbname'),
        NIST_KEY: ecs.Secret.fromSecretsManager(nistSecret, 'NIST_KEY'),
      },
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'server',
        logRetention: logs.RetentionDays.ONE_MONTH,
      }),
      healthCheck: {
        command: ['CMD-SHELL', 'wget -qO- http://localhost:4000/health || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(60),
      },
    });

    // ── Client Task Definition ─────────────────────────────────────────────
    const clientTaskDef = new ecs.FargateTaskDefinition(this, 'ClientTaskDef', {
      cpu: 256,
      memoryLimitMiB: 512,
      executionRole,
    });

    clientTaskDef.addContainer('client', {
      image: ecs.ContainerImage.fromEcrRepository(clientRepo, 'latest'),
      portMappings: [{ containerPort: 80 }],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'client',
        logRetention: logs.RetentionDays.ONE_MONTH,
      }),
      healthCheck: {
        command: ['CMD-SHELL', 'wget -qO- http://localhost/health || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(30),
      },
    });

    // ── ALB ────────────────────────────────────────────────────────────────
    const alb = new elbv2.ApplicationLoadBalancer(this, 'ALB', {
      vpc,
      internetFacing: true,
      loadBalancerName: 'vanquish',
    });

    const serverTG = new elbv2.ApplicationTargetGroup(this, 'ServerTG', {
      vpc,
      port: 4000,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targetType: elbv2.TargetType.IP,
      healthCheck: {
        path: '/health',
        healthyHttpCodes: '200',
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    const clientTG = new elbv2.ApplicationTargetGroup(this, 'ClientTG', {
      vpc,
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targetType: elbv2.TargetType.IP,
      healthCheck: {
        path: '/',
        healthyHttpCodes: '200',
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    const listener = alb.addListener('HttpListener', {
      port: 80,
      defaultTargetGroups: [clientTG],
    });

    // /api and /api/* route to backend — must have higher priority than default
    listener.addAction('ApiAction', {
      priority: 10,
      conditions: [elbv2.ListenerCondition.pathPatterns(['/api', '/api/*'])],
      action: elbv2.ListenerAction.forward([serverTG]),
    });

    // ── ECS Services ───────────────────────────────────────────────────────
    const serverService = new ecs.FargateService(this, 'ServerService', {
      cluster,
      taskDefinition: serverTaskDef,
      serviceName: 'vanquish-server',
      desiredCount: 1,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      circuitBreaker: { rollback: true },
    });

    const clientService = new ecs.FargateService(this, 'ClientService', {
      cluster,
      taskDefinition: clientTaskDef,
      serviceName: 'vanquish-client',
      desiredCount: 1,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      circuitBreaker: { rollback: true },
    });

    serverService.attachToApplicationTargetGroup(serverTG);
    clientService.attachToApplicationTargetGroup(clientTG);

    // ── Security Group Rules ───────────────────────────────────────────────
    serverService.connections.allowFrom(alb, ec2.Port.tcp(4000));
    clientService.connections.allowFrom(alb, ec2.Port.tcp(80));
    database.connections.allowFrom(serverService, ec2.Port.tcp(5432));

    // ── Outputs ────────────────────────────────────────────────────────────
    new cdk.CfnOutput(this, 'AppUrl', {
      value: `http://${alb.loadBalancerDnsName}`,
      description: 'Application URL',
    });

    new cdk.CfnOutput(this, 'ServerEcrUri', {
      value: serverRepo.repositoryUri,
      description: 'Server ECR repository URI',
    });

    new cdk.CfnOutput(this, 'ClientEcrUri', {
      value: clientRepo.repositoryUri,
      description: 'Client ECR repository URI',
    });

    new cdk.CfnOutput(this, 'NistSecretArn', {
      value: nistSecret.secretArn,
      description: 'Set your NIST API key here in Secrets Manager',
    });
  }
}
