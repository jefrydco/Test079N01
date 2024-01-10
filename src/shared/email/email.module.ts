import { MailerModule } from '@nestjs-modules/mailer'
import { Global, Module } from '@nestjs/common'
import { EMailConfigService } from './email-config.service'
import { BullModule } from '@nestjs/bull'
import { MAIL_QUEUE } from './email.constants'
import { EmailService } from './email.service'
import { EmailConsumer } from './email.consumer'

@Global()
@Module({
  imports: [
    MailerModule.forRootAsync({
      useClass: EMailConfigService,
    }),
    BullModule.registerQueue({ name: MAIL_QUEUE }),
  ],
  providers: [EmailService, EmailConsumer],
  exports: [EmailService],
})
export class EmailModule {}
