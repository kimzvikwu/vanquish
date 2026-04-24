#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { VanquishStack } from '../lib/vanquish-stack';

const app = new cdk.App();

new VanquishStack(app, 'VanquishStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
  description: 'Vanquish vulnerability management platform',
});
