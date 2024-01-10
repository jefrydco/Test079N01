import { Controller, Get } from '@nestjs/common'

@Controller()
export class HealthCheckController {
  @Get('/health')
  health(): string {
    return 'Ok'
  }
}
