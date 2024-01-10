import { Module } from '@nestjs/common'
import { HealthCheckController } from './health-check.controller'

@Module({
  imports: [],
  providers: [],
  controllers: [HealthCheckController],
})
export class HealthCheckModule {}
