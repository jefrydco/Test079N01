import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { User } from 'src/entities/users';
import { encryptPassword } from 'src/utils/transform';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { PasswordResetRepository } from 'src/repositories/password-reset.repository';
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { LoginAttempt } from 'src/entities/login_attempts';
import { EmailVerificationRepository } from 'src/repositories/email-verifications.repository';
import { MoreThan } from 'typeorm';
import { LoginDto } from './dto/login.dto';
import { RequestPasswordResetDto } from './dtos/request-password-reset.dto';
import { RegisterNewUserDto } from './dtos/register-new-user.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

export class RegisterUserResponseDto {
  success: boolean;
  message: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly loginAttemptRepository: LoginAttemptRepository,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
    private readonly emailVerificationRepository: EmailVerificationRepository,
    private readonly passwordResetRepository: PasswordResetRepository, // Keep the PasswordResetRepository from existing code
  ) {}

  async registerNewUser(registerUserDto: RegisterNewUserDto): Promise<RegisterUserResponseDto> {
    const { username, password, email } = registerUserDto;

    // Validate input parameters
    if (!username || !password || !email) {
      throw new BadRequestException('Username, password, and email are required.');
    }
    if (password.length < 8) { // Keep the password length check from existing code
      throw new BadRequestException('Password must be at least 8 characters long.');
    }

    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email format.');
    }

    const userExists = await this.userRepository.findOne({
      where: [{ username }, { email }],
    });

    if (userExists) {
      throw new ConflictException('Username or email already in use.');
    }

    const passwordHash = await encryptPassword(password);
    const emailConfirmationToken = crypto.randomBytes(16).toString('hex');

    const newUser = this.userRepository.create({ // Use the create method from existing code
      username,
      password_hash: passwordHash,
      email,
      is_active: false, // Keep the is_active flag from existing code
      last_login: null,
      emailConfirmationToken,
      created_at: new Date(),
      updated_at: new Date(),
    });

    await this.userRepository.save(newUser);

    await this.emailService.sendMail({ // Keep the sendMail method from existing code
      to: email,
      subject: 'Email Confirmation',
      template: 'email-confirmation.hbs',
      context: {
        token: emailConfirmationToken,
      },
    });

    return {
      success: true,
      message: 'User registered successfully. Please check your email to confirm your account.',
    };
  }

  // ... rest of the AuthService code including login and recordLoginAttempt methods ...

  async confirmEmail(token: string): Promise<string> {
    if (!token) {
      throw new BadRequestException('Confirmation token is required.');
    }

    const user = await this.userRepository.findOne({ where: { emailConfirmationToken: token } });

    if (!user) {
      throw new NotFoundException('Invalid confirmation token.');
    }

    user.is_active = true;
    user.updated_at = new Date();
    user.emailConfirmationToken = null;

    await this.userRepository.save(user);

    await this.emailService.sendConfirmationEmail({ email: user.email, token }); // Keep the sendConfirmationEmail method from existing code

    return 'Email has been successfully confirmed.';
  }

  // ... rest of the AuthService code including login, requestPasswordReset, and verifyEmail methods ...
}
