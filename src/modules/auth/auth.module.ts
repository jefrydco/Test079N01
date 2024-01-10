import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserRepository } from 'src/repositories/users.repository';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { PasswordResetRepository } from 'src/repositories/password-resets.repository'; // Added from new code
import { EmailService } from 'src/shared/email/email.service';
import { User } from 'src/entities/users';
import { EmailVerification } from 'src/entities/email_verifications';
import { PasswordReset } from 'src/entities/password_resets'; // Added from new code
import { LoginAttempt } from 'src/entities/login_attempts'; // Added from existing code

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      EmailVerification,
      PasswordReset, // Added from new code
      UserRepository,
      LoginAttemptRepository,
      LoginAttempt, // Added from existing code
      PasswordResetRepository, // Added from new code
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
