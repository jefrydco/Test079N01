import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserRepository } from 'src/repositories/users.repository';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { PasswordResetRepository } from 'src/repositories/password-resets.repository';
import { EmailService } from 'src/shared/email/email.service';
import { User } from 'src/entities/users';
import { EmailVerification } from 'src/entities/email_verifications';
import { PasswordReset } from 'src/entities/password_resets';
import { LoginAttempt } from 'src/entities/login_attempts';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      EmailVerification,
      PasswordReset,
      UserRepository,
      LoginAttemptRepository,
      LoginAttempt,
      PasswordResetRepository,
    ]),
    JwtModule.register({}), // Assuming JwtModule is configured elsewhere
  ],
  providers: [
    AuthService,
    EmailService,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
