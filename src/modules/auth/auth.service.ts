import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { EmailVerificationRepository } from 'src/repositories/email-verifications.repository';
import { PasswordResetRepository } from 'src/repositories/password-resets.repository';
import { encryptPassword } from 'src/utils/transform';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { User } from 'src/entities/users';
import { LoginAttempt } from 'src/entities/login_attempts';
import { PasswordReset } from 'src/entities/password_resets';
import { MoreThan } from 'typeorm';
import { RecordLoginAttemptDto } from './dtos/record-login-attempt.dto'; // Added import for RecordLoginAttemptDto

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
    private readonly emailVerificationRepository: EmailVerificationRepository,
    private readonly passwordResetRepository: PasswordResetRepository,
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
      emailConfirmationToken,
      created_at: new Date(),
      updated_at: new Date(),
    });

    await this.userRepository.save(newUser);

    await this.emailService.sendMail({
      to: email,
      subject: 'Email Confirmation',
      template: 'email-confirmation',
      context: {
        token: emailConfirmationToken,
      },
    });

    return {
      success: true,
      message: 'User registered successfully. Please check your email to confirm your account.',
    };
  }

  async login(username: string, password: string): Promise<{ token: string; message: string }> {
    if (!username || !password) {
      throw new BadRequestException('Username and password are required.');
    }

    const user = await this.userRepository.findOne({ where: { username } });

    if (!user) {
      await this.recordLoginAttempt({ userId: undefined, success: false, ipAddress: undefined, username });
      throw new NotFoundException('Invalid credentials.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      await this.recordLoginAttempt({ userId: user.id, success: false, ipAddress: undefined, username });
      throw new UnauthorizedException('Invalid credentials.');
    }

    user.last_login = new Date();
    await this.userRepository.save(user);

    await this.recordLoginAttempt({ userId: user.id, success: true, ipAddress: undefined, username });

    const token = this.jwtService.sign({ userId: user.id });

    return {
      token,
      message: 'Login successful.'
    };
  }

  async recordLoginAttempt(recordLoginAttemptDto: RecordLoginAttemptDto): Promise<void> {
    const { userId, success, ipAddress, username } = recordLoginAttemptDto;

    let user_id = userId;
    if (!user_id || !ipAddress) {
      if (!username) {
        throw new BadRequestException('User ID or username and IP address must not be empty.');
      }
      const user = await this.userRepository.findOne({ where: { username } });
      if (!user) {
        throw new NotFoundException('User does not exist.');
      }
      user_id = user.id;
    }

    const loginAttempt = this.loginAttemptRepository.create({
      user_id: user_id,
      attempt_time: new Date(),
      success: success,
      ip_address: ipAddress || '',
    });

    await this.loginAttemptRepository.save(loginAttempt);

    if (!success) {
      const failedAttempts = await this.loginAttemptRepository.count({
        where: { user_id: user_id, success: false, attempt_time: MoreThan(new Date(Date.now() - 3600000)) },
      });
      if (failedAttempts >= 5) {
        const user = await this.userRepository.findOneBy({ id: user_id });
        if (user) {
          user.is_active = false;
          await this.userRepository.save(user);
        }
      }
    }
  }

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

    await this.emailService.sendConfirmationEmail({ email: user.email, token });

    return 'Email has been successfully confirmed.';
  }

  async requestPasswordReset(email: string): Promise<string> {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user || !user.is_active) {
      throw new NotFoundException('No active user found with the provided email.');
    }

    const token = crypto.randomBytes(16).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000);

    const passwordReset = new PasswordReset();
    passwordReset.token = token;
    passwordReset.expires_at = expiresAt;
    passwordReset.user = user;
    passwordReset.used = false;

    await this.passwordResetRepository.save(passwordReset);

    await this.emailService.sendMail({
      to: email,
      subject: 'Password Reset Request',
      template: 'password-reset',
      context: { token },
    });

    return 'A password reset email has been sent to your email address.';
  }

  // ... rest of the AuthService code ...
}
