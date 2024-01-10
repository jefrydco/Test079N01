import { HealthCheckModule } from './health-check/health-check.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ShopsModule } from './shops/shops.module';

export default [HealthCheckModule, UsersModule, ShopsModule, AuthModule];
