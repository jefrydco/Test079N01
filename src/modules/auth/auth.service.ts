import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { PasswordResetRepository } from 'src/repositories/password-resets.repository'; // Added import for PasswordResetRepository
import { encryptPassword } from 'src/utils/transform';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { User } from 'src/entities/users';
import { LoginAttempt } from 'src/entities/login_attempts';
import { PasswordReset } from 'src/entities/password_resets'; // Added import for PasswordReset
import { MoreThan } from 'typeorm'; // Added import for MoreThan

export class RegisterUserDto {
  username: string;
  password: string;
  email: string;
}

export class RegisterUserResponseDto {
  success: boolean;
  message: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly passwordResetRepository: PasswordResetRepository, // Added PasswordResetRepository to constructor
    private readonly loginAttemptRepository: LoginAttemptRepository,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
  ) {}

  async registerNewUser(registerUserDto: RegisterUserDto): Promise<RegisterUserResponseDto> {
    const { username, password, email } = registerUserDto;

    if (!username || !password || !email) {
      throw new BadRequestException('Username, password, and email are required.');
    }

    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email format.');
    }

    const userExists = await this.userRepository.findOne({
      where: [{ username }, { email }],
    });

    if (userExists) {
      return {
        success: false,
        message: 'Username or email already registered.',
      };
    }

    const passwordHash = await encryptPassword(password);
    const emailConfirmationToken = crypto.randomBytes(16).toString('hex');

    const newUser = this.userRepository.create({
      username,
      password_hash: passwordHash,
      email,
      is_active: false,
      last_login: null,
      emailConfirmationToken, // Store the email confirmation token
      created_at: new Date(), // Added from existing code
      updated_at: new Date(), // Added from existing code
    });

    await this.userRepository.save(newUser);

    await this.emailService.sendMail({
      to: email,
      subject: 'Email Confirmation',
      template: 'email-confirmation', // Use the template name from the existing code
      context: {
        token: emailConfirmationToken,
      },
    });

    return {
      success: true,
      message: 'User registered successfully. Please check your email to confirm your account.',
    };
  }

  // ... rest of the AuthService code including login, recordLoginAttempt, confirmEmail, resetPassword methods ...
}
