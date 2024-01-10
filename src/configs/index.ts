import { join } from 'path';
import { NODE_ENV } from 'src/constants';
import type { Config } from './config.interface';
import { DriverType } from '@codebrew/nestjs-storage';
import { getCredentials } from 'src/utils/credentials';
import { config } from 'dotenv';

config();

export default (): Config => {
  const credentials = getCredentials(process.env.APP_ENV || 'development');

  return {
    app: {
      nodeEnv: (process.env.NODE_ENV as NODE_ENV) || NODE_ENV.PRODUCTION,
      port: +process.env.APP_PORT || 3000,
      fallbackLanguage: process.env.APP_FALLBACK_LANGUAGE || 'en',
      headerLanguage: process.env.APP_HEADER_LANGUAGE || 'x-custom-lang',
    },
    database: {
      type: 'postgres',
      database:
        process.env.NODE_ENV === 'test'
          ? `${process.env.DATABASE_NAME}_test`
          : process.env.DATABASE_NAME || credentials?.database?.name || 'example',
      host: process.env.DATABASE_HOST || credentials?.database?.host || 'localhost',
      username: process.env.DATABASE_USERNAME || credentials?.database?.username || 'postgres',
      password: process.env.DATABASE_PASSWORD || credentials?.database?.password || 'postgres',
      port: +process.env.DATABASE_PORT || +credentials?.database?.port || 5432,
    },
    storage: {
      default: process.env.STORAGE_DISK || 'local',
      disks: {
        local: {
          driver: DriverType.LOCAL,
          config: {
            root: join(__dirname, '..', 'uploads'),
            publicUrl: `${process.env.API_URL}/uploads`,
          },
        },
        s3: {
          driver: DriverType.S3,
          config: {
            key: process.env.S3_KEY || credentials?.aws?.s3_key || '',
            secret: process.env.S3_SECRET || credentials?.aws?.s3_secret || '',
            endpoint:
              process.env.S3_ENDPOINT ||
              credentials?.aws?.s3_endpoint ||
              `https://s3.${process.env.AWS_DEFAULT_REGION || 'ap-northeast-1'}.amazonaws.com`,
            bucket: process.env.S3_BUCKET || credentials?.aws?.s3_bucket || '',
            region: process.env.AWS_DEFAULT_REGION || 'ap-northeast-1',
          },
        },
      },
    },
    fileConfig: {
      imageSize: {
        width: +process.env.IMAGE_SIZE_WIDTH,
        height: +process.env.IMAGE_SIZE_HEIGHT,
      },
    },
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: +process.env.REDIS_PORT || 6379,
    },
    jwt: {
      accessSecret:
        process.env.JWT_ACCESS_SECRET || credentials?.jwt?.access_token_secret || 'secret',
      refreshSecret:
        process.env.JWT_REFRESH_SECRET || credentials?.jwt?.refresh_token_secret || 'secret',
      expiresIn: process.env.JWT_EXPIRES_IN || '7d',
      refreshIn: process.env.JWT_REFRESH_IN || '30d',
      bcryptSaltOrRound: 10,
    },
    authentication: {
      sendConfirmationEmail: Boolean(process.env.AUTH_SEND_CONFIRMATION_EMAIL) || false,
      confirmationUrl: process.env.AUTH_CONFIRMATION_URL || 'http://localhost:3000/confirm',
      confirmationIn: +process.env.AUTH_CONFIRMATION_IN || 24,
      resetPasswordUrl:
        process.env.AUTH_RESET_PASSWORD_URL || 'http://localhost:3000/reset-password',
      resetPasswordIn: +process.env.AUTH_RESET_PASSWORD_IN || 1,
      maximumAttempts: 10,
    },
    mail: {
      provider: process.env.MAIL_PROVIDER || 'maildev',
      mailFrom: process.env.MAIL_FROM || '',
      maildev: {
        host: process.env.MAILDEV_HOST || 'localhost',
        username: process.env.MAILDEV_USERNAME || 'maildev',
        password: process.env.MAILDEV_PASSWORD || 'maildev',
      },
      ses: {
        username: process.env.SES_USERNAME || credentials?.ses?.username || '',
        password: process.env.SES_PASSWORD || credentials?.ses?.password || '',
      },
      sendgrid: {
        apiKey: process.env.SENDGRID_API_KEY || credentials?.sendgrid?.api_key || '',
      },
    },
    swagger: {
      path: process.env.SWAGGER_PATH || 'api-docs',
      username: process.env.SWAGGER_USERNAME || credentials?.swagger?.username || 'swagger',
      password: process.env.SWAGGER_PASSWORD || credentials?.swagger?.password || 'swagger',
    },
    common: {
      appName: process.env.APP_NAME || credentials?.common?.app_name || 'nestjs project',
    },
    basicAuth: {
      username: process.env.BASIC_AUTH_USERNAME || credentials?.basicAuth?.username || 'admin',
      password: process.env.BASIC_AUTH_PASSWORD || credentials?.basicAuth?.password || 'admin',
    },
    twilio: {
      accountSid: process.env.TWILIO_ACCOUNT_SID || credentials?.twilioLogin?.sid,
      authToken: process.env.TWILIO_AUTH_TOKEN || credentials?.twilioLogin?.token,
      verificationServiceSid:
        process.env.TWILIO_VERIFICATION_SERVICE_SID || credentials?.twilioLogin?.serviceId,
      recaptchaSecretKey:
        process.env.RECAPTCHA_SECRET_KEY || credentials?.twilioLogin?.recaptchaSecretKey,
      recaptchaScore: process.env.RECAPTCHA_SCORE || credentials?.twilioLogin?.recaptchaScore,
    },
    deepLink: {
      iosAppStoreId: process.env.IOS_APP_STORE_ID || credentials?.deepLink?.iosAppStoreId,
      iosBundleId: process.env.IOS_BUNDLE_ID || credentials?.deepLink?.iosBundleId,
      iosAppLink: process.env.IOS_APP_LINK || credentials?.deepLink?.iosAppLink,
      androidPackageName:
        process.env.ANDROID_PACKAGE_NAME || credentials?.deepLink?.androidPackageName,
      androidAppLink: process.env.ANDROID_APP_LINK || credentials?.deepLink?.androidPackageName,
      androidCertFingerprints:
        process.env.ANDROID_CERT_FINGERPRINTS || credentials?.deepLink?.androidCertFingerprints,
      firebaseDomain: process.env.FIREBASE_DOMAIN || credentials?.deepLink?.firebaseDomain,
    },
    line: {
      clientId: process.env.LINE_CLIENT_ID || credentials?.line?.clientId || 'clientId',
      clientSecret:
        process.env.LINE_CLIENT_SECRET || credentials?.line?.secretKey || 'clientSecret',
    },
    rollbar: {
      accessToken: process.env.ROLLBAR_ACCESS_TOKEN || credentials?.rollbar?.accessToken,
    },
    scoutApm: {
      keyId: process.env.SCOUT_KEY_ID || credentials?.scoutApm?.keyId,
    },
  };
};

export * from './config.interface';
