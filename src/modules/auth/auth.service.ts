import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { encryptPassword } from 'src/utils/transform'; // Added import for encryptPassword
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { User } from 'src/entities/users';
import { LoginAttempt } from 'src/entities/login_attempts';

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

    const passwordHash = await encryptPassword(password); // Use encryptPassword utility
    const emailConfirmationToken = crypto.randomBytes(16).toString('hex');

    const newUser = this.userRepository.create({
      username,
      password_hash: passwordHash,
      email,
      is_active: false,
      last_login: null,
      emailConfirmationToken, // Store the email confirmation token
    });

    await this.userRepository.save(newUser);

    await this.emailService.sendMail({
      to: email,
      subject: 'Email Confirmation',
      // Assuming there is a template for email confirmation
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

    const token = this.jwtService.sign({ userId: user.id });

    return {
      token,
      message: 'Login successful.'
    };
  }

  async recordLoginAttempt(userId: number, success: boolean, ipAddress?: string, username?: string): Promise<void> {
    if (!userId || !ipAddress) {
      if (!username) {
        throw new BadRequestException('User ID or username and IP address must not be empty.');
      }
      const user = await this.userRepository.findOne({ where: { username } });
      if (!user) {
        throw new NotFoundException('User does not exist.');
      }
      userId = user.id;
    }

    const loginAttempt = new LoginAttempt();
    loginAttempt.user_id = userId;
    loginAttempt.attempt_time = new Date();
    loginAttempt.success = success;
    loginAttempt.ip_address = ipAddress || '';
    await this.loginAttemptRepository.save(loginAttempt);

    if (!success) {
      const failedAttempts = await this.loginAttemptRepository.count({
        where: { user_id: userId, success: false },
      });
      if (failedAttempts >= 5) {
        const user = await this.userRepository.findOneBy({ id: userId });
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
    user.emailConfirmationToken = null; // Invalidate the token

    await this.userRepository.save(user);

    await this.emailService.sendConfirmationEmail({ email: user.email, token });

    return 'Email has been successfully confirmed.';
  }

  // ... rest of the AuthService code ...
}
