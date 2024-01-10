import { ISendMailOptions } from '@nestjs-modules/mailer'
import { InjectQueue } from '@nestjs/bull'
import { Injectable, Logger } from '@nestjs/common'
import { Queue } from 'bull'
import { MAIL_QUEUE, SEND_MAIL_JOB } from './email.constants'

@Injectable()
export class EmailService {
  constructor(@InjectQueue(MAIL_QUEUE) private readonly mailQueue: Queue) {}

  private logger = new Logger(EmailService.name)

  async sendMail(options: ISendMailOptions) {
    try {
      if (process.env.NODE_ENV === 'test') {
        return true
      }

      await this.mailQueue.add(SEND_MAIL_JOB, options)
      return true
    } catch (e) {
      this.logger.error('An error occur while adding send mail job', e)
      return false
    }
  }
}
