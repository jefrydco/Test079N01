import { HealthCheckModule } from './health-check/health-check.module';
import { UsersModule } from './users/users.module';
import { ShopsModule } from './shops/shops.module';
import { AuthModule } from './auth/auth.module'; // Corrected import path

export default [HealthCheckModule, UsersModule, ShopsModule, AuthModule];
