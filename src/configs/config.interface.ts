import { NODE_ENV } from 'src/constants';
import { StorageModuleOptions } from '@codebrew/nestjs-storage';
export interface Config {
  app: AppConfig;
  database: DatabaseConfig;
  redis: RedisConfig;
  rollbar: RollbarConfig;
  common: CommonConfig;
  scoutApm: ScoutApmConfig;
  jwt: JWTConfig;
  basicAuth: BasicAuthConfig;
  twilio: TwilioConfig;
  deepLink: DeepLinkConfig;
  line: LineConfig;
  swagger: SwaggerConfig;
  mail: MailConfig;
  authentication: AuthenticationConfig;
  fileConfig: FileConfig;
  storage: StorageConfig;
}

export interface AppConfig {
  nodeEnv: NODE_ENV;
  port: number;
  fallbackLanguage: string;
  headerLanguage: string;
}

export interface FileConfig {
  imageSize: {
    width: number;
    height: number;
  };
}

export interface DatabaseConfig {
  type: string;
  database: string;
  host: string;
  username: string;
  password: string;
  port: number;
}

export interface RollbarConfig {
  accessToken: string;
}

export interface ScoutApmConfig {
  keyId: string;
}

export interface CommonConfig {
  appName: string;
}

export interface JWTConfig {
  accessSecret: string;
  refreshSecret: string;
  expiresIn: string;
  refreshIn: string;
  bcryptSaltOrRound: string | number;
}

export interface RedisConfig {
  host: string;
  port: number;
}

export interface BasicAuthConfig {
  username: string;
  password: string;
}

export interface TwilioConfig {
  accountSid: string;
  authToken: string;
  verificationServiceSid: string;
  recaptchaSecretKey: string;
  recaptchaScore: string;
}

export interface DeepLinkConfig {
  iosAppStoreId: string;
  iosBundleId: string;
  androidPackageName: string;
  androidAppLink: string;
  iosAppLink: string;
  firebaseDomain: string;
  androidCertFingerprints: string;
}

export interface LineConfig {
  clientId: string;
  clientSecret: string;
}

export interface SwaggerConfig {
  path: string;
  username: string;
  password: string;
}

export interface MailConfig {
  provider: string;
  mailFrom: string;
  maildev: {
    host: string;
    username: string;
    password: string;
  };
  ses: {
    username: string;
    password: string;
  };
  sendgrid: {
    apiKey: string;
  };
}

export interface AuthenticationConfig {
  sendConfirmationEmail: boolean;
  confirmationUrl: string;
  confirmationIn: number;
  resetPasswordUrl: string;
  resetPasswordIn: number;
  passwordPattern?: string | RegExp;
  maximumAttempts?: number;
  unlockIn?: string;
  unlockStrategy?: string;
  unlockAccessUrl?: string;
}

export interface StorageConfig extends StorageModuleOptions {}
