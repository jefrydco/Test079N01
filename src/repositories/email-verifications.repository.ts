import { Injectable } from '@nestjs/common';
import { BaseRepository } from 'src/shared/base.repository';
import { EmailVerification } from '@entities/email_verifications';
import { EntityManager } from 'typeorm';

@Injectable()
export class EmailVerificationRepository extends BaseRepository<EmailVerification> {
  constructor(manager: EntityManager) {
    super(EmailVerification, manager);
  }

  async create(emailVerificationData: Partial<EmailVerification>): Promise<EmailVerification> {
    const emailVerification = this.manager.create(EmailVerification, emailVerificationData);
    return this.save(emailVerification);
  }

  async save(emailVerification: EmailVerification): Promise<EmailVerification> {
    return this.manager.save(emailVerification);
  }
}

@Injectable()
export class EmailVerificationRepository extends BaseRepository<EmailVerification> {}
