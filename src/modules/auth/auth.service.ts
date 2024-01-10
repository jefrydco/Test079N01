import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { EmailVerificationRepository } from 'src/repositories/email-verifications.repository'; // Added from patch
import { encryptPassword } from 'src/utils/transform';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { User } from 'src/entities/users';
import { LoginAttempt } from 'src/entities/login_attempts';
import { MoreThan } from 'typeorm'; // Added from existing code

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
    private readonly loginAttemptRepository: LoginAttemptRepository,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
    private readonly emailVerificationRepository: EmailVerificationRepository, // Added from patch
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

    const passwordHash = await bcrypt.hash(password, 10); // Use bcrypt directly as in existing code
    const emailConfirmationToken = crypto.randomBytes(16).toString('hex');

    const newUser = this.userRepository.create({
      username,
      password_hash: passwordHash,
      email,
      is_active: false,
      last_login: null,
      emailConfirmationToken, // Store the email confirmation token
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

  async confirmEmail(email: string, confirmationCode: string): Promise<{ status: number; message: string }> {
    if (!email || !confirmationCode) {
      throw new BadRequestException('Email and confirmation code are required.');
    }

    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email format.');
    }
    
    const emailVerification = await this.emailVerificationRepository.findOne({
      where: { token: confirmationCode, verified: false },
    });

    if (!emailVerification || new Date() > emailVerification.expires_at) {
      throw new NotFoundException('Invalid or expired confirmation code.');
    }

    const user = await this.userRepository.findOneBy({ id: emailVerification.user_id });
    user.is_active = true;
    await this.userRepository.save(user);

    await this.emailVerificationRepository.remove(emailVerification);

    await this.emailService.sendConfirmationEmail({ email: user.email, token: confirmationCode });

    return {
      status: 200,
      message: 'Email confirmed successfully.'
    };
  }

  async login(username: string, password: string): Promise<{ access_token: string; message: string }> {
    if (!username || !password) {
      throw new BadRequestException('Username and password are required.');
    }

    const user = await this.userRepository.findOne({ where: { username } });

    if (!user) {
      await this.recordLoginAttempt(undefined, false, undefined, username);
      throw new NotFoundException('Invalid credentials.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      await this.recordLoginAttempt(user.id, false, undefined, username);
      throw new UnauthorizedException('Invalid credentials.');
    }

    user.last_login = new Date();
    await this.userRepository.save(user);

    await this.recordLoginAttempt(user.id, true, undefined, username);

    const access_token = this.jwtService.sign({ userId: user.id }); // Renamed token to access_token to match existing code

    return {
      access_token,
      message: 'Login successful.'
    };
  }

  async recordLoginAttempt(userId: number, success: boolean, ipAddress?: string, username?: string): Promise<void> {
    let user_id = userId;
    if (!user_id) {
      if (!username) {
        throw new BadRequestException('User ID or username and IP address must not be empty.');
      }
      const user = await this.userRepository.findOne({ where: { username } });
      if (!user) {
        throw new NotFoundException('User does not exist.');
      }
      user_id = user.id;
    } else {
      const user = await this.userRepository.findOne({ where: { id: user_id } });
      if (!user) {
        throw new NotFoundException('User not found.');
      }
    }

    if (!ipAddress) {
      throw new BadRequestException('IP address is required.');
    }

    const loginAttempt = this.loginAttemptRepository.create({
      user_id: user_id,
      attempt_time: new Date(),
      success: success,
      ip_address: ipAddress,
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
