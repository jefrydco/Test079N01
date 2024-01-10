import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { BaseRepository } from 'src/shared/base.repository';
import { User } from '@entities/users';
import { EmailVerification } from '@entities/email_verifications';

@Injectable()
export class UserRepository extends BaseRepository<User> {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(EmailVerification)
    private readonly emailVerificationRepository: Repository<EmailVerification>,
  ) {
    super(userRepository);
  }

  async registerNewUser(username: string, passwordHash: string, email: string): Promise<User> {
    // Implement the user registration logic here
    // This is a placeholder function and should be implemented according to the actual requirement
  }
}

@Injectable()
export class UserRepository extends BaseRepository<User> {}
