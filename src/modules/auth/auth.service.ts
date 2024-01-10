import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { EmailVerificationRepository } from 'src/repositories/email-verifications.repository';
import { PasswordResetRepository } from 'src/repositories/password-resets.repository';
import { encryptPassword } from 'src/utils/transform'; // Keep this if it's used elsewhere in the existing code
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { User } from 'src/entities/users';
import { LoginAttempt } from 'src/entities/login_attempts';
import { PasswordReset } from 'src/entities/password_resets';
import { MoreThan } from 'typeorm';
import { LoginDto } from './dto/login.dto'; // Added from new code
import { RecordLoginAttemptDto } from './dtos/record-login-attempt.dto'; // Keep this if it's used elsewhere in the existing code

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
    private readonly emailVerificationRepository: EmailVerificationRepository, // Keep this if it's used elsewhere in the existing code
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
      throw a BadRequestException('Invalid email format.');
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

    // Use bcrypt directly if encryptPassword is not a custom function that does more than bcrypt
    const passwordHash = await bcrypt.hash(password, 10);
    const emailConfirmationToken = crypto.randomBytes(16).toString('hex');

    const newUser = this.userRepository.create({
      username,
      password_hash: passwordHash,
      email,
      is_active: false,
      last_login: null,
      emailConfirmationToken, // Keep this if it's used elsewhere in the existing code
      created_at: new Date(), // Keep this if it's used elsewhere in the existing code
      updated_at: new Date(), // Keep this if it's used elsewhere in the existing code
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

  async login(loginDto: LoginDto): Promise<{ access_token: string; message: string }> {
    const { username, password } = loginDto;

    if (!username || !password) {
      throw new BadRequestException('Username and password are required.');
    }

    const user = await this.userRepository.findOne({ where: { username } });

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      await this.recordLoginAttempt({ userId: undefined, success: false, ipAddress: undefined, username }); // Use DTO if it's required by the existing code
      throw new UnauthorizedException('Invalid credentials.');
    }

    user.last_login = new Date();
    await this.userRepository.save(user);

    await this.recordLoginAttempt({ userId: user.id, success: true, ipAddress: undefined, username }); // Use DTO if it's required by the existing code
    const access_token = this.jwtService.sign({ userId: user.id });

    return {
      access_token,
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

  // ... rest of the AuthService code ...
}
