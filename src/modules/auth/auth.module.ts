import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserRepository } from 'src/repositories/users.repository';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { EmailService } from 'src/shared/email/email.service';
import { User } from 'src/entities/users';
import { EmailVerification } from 'src/entities/email_verifications';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, EmailVerification]),
    JwtModule.register({}), // Assuming JwtModule is configured elsewhere
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    UserRepository,
    LoginAttemptRepository,
    EmailService,
  ],
  exports: [AuthService],
})
export class AuthModule {}
