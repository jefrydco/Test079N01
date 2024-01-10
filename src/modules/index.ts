import { HealthCheckModule } from './health-check/health-check.module';
import { UsersModule } from './users/users.module';
import { ShopsModule } from './shops/shops.module';
import { AuthModule } from './auth/auth.module';
import { EmailVerificationModule } from './email-verification/email-verification.module'; // Keep this from existing code

export default [
  HealthCheckModule,
  UsersModule,
  EmailVerificationModule, // Keep this from existing code
  ShopsModule,
  AuthModule,
];
