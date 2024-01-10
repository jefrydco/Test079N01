import { HealthCheckModule } from './health-check/health-check.module';
import { EmailVerificationModule } from './email-verification/email-verification.module';
import { UsersModule } from './users/users.module';
import { ShopsModule } from './shops/shops.module';
import { AuthModule } from './auth/auth.module';

export default [
  HealthCheckModule,
  UsersModule,
  EmailVerificationModule, // Added from new code
  ShopsModule,
  AuthModule,
];
