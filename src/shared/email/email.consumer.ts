import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer'
import { Process, Processor } from '@nestjs/bull'
import { Job } from 'bull'
import { Logger } from '@nestjs/common'
import { MAIL_QUEUE, SEND_MAIL_JOB } from './email.constants'

@Processor(MAIL_QUEUE)
export class EmailConsumer {
  constructor(private readonly mailService: MailerService) {}

  private logger = new Logger(EmailConsumer.name)

  @Process(SEND_MAIL_JOB)
  async sendMail({ data }: Job<ISendMailOptions>) {
    try {
      await this.mailService.sendMail(data)
      this.logger.log(
        `Email ${data.template || ''} has been sent with context ${
          JSON.stringify(data.context) || ''
        }`,
      )
    } catch (e) {
      this.logger.error(
        `An error occur while sending email ${data.template || ''} with context ${
          JSON.stringify(data.context) || ''
        }`,
        e,
      )
    }
  }
}
