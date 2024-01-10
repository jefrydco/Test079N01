
import { ISendMailOptions } from '@nestjs-modules/mailer'
import { InjectQueue } from '@nestjs/bull'
import { Injectable, Logger } from '@nestjs/common'
import { Queue } from 'bull'
import { MAIL_QUEUE, SEND_MAIL_JOB } from './email.constants'
import { join } from 'path'

interface EmailConfirmationDTO {
  email: string;
  token: string;
}

@Injectable()
export class EmailService {
  constructor(@InjectQueue(MAIL_QUEUE) private readonly mailQueue: Queue) {}

  private logger = new Logger(EmailService.name)

  async sendConfirmationEmail(dto: EmailConfirmationDTO) {
    const options: ISendMailOptions = {
      to: dto.email,
      subject: 'Confirm your email',
      template: join(__dirname, 'templates', 'email-confirmation.hbs'),
      context: {
        token: dto.token,
        url: 'http://yourapp.com/confirm-email',
      },
    };
    return this.sendMail(options);
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<boolean> {
    const options: ISendMailOptions = {
      to: email,
      subject: 'Reset your password',
      template: join(__dirname, 'templates', 'reset-password.hbs'),
      context: {
        token: token,
        url: 'http://yourapp.com/reset-password',
      },
    };
    return this.sendMail(options);
  }

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
