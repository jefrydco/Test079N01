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
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { LoginAttempt } from 'src/entities/login_attempts';
import { EmailVerificationRepository } from 'src/repositories/email-verifications.repository';
import { MoreThan } from 'typeorm';
import { LoginDto } from './dto/login.dto'; // Added from new code

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
    private readonly emailVerificationRepository: EmailVerificationRepository, // Keep this from existing code
  ) {}

  async registerNewUser(registerUserDto: RegisterUserDto): Promise<RegisterUserResponseDto> {
    const { username, password, email } = registerUserDto;

    // Validate input parameters
    if (!username || !password || !email) {
      throw new BadRequestException('Username, password, and email are required.');
    }
    if (password.length < 8) {
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
      template: 'email-confirmation.hbs', // Use template from existing code
      context: {
        token: emailConfirmationToken,
      },
    });

    return {
      success: true,
      message: 'User registered successfully. Please check your email to confirm your account.',
    };
  }

  async login(loginDto: LoginDto): Promise<{ token: string; message: string }> {
    if (!loginDto.username || !loginDto.password) {
      throw new BadRequestException('Username and password are required.');
    }

    const user = await this.userRepository.findOne({ where: { username: loginDto.username } });

    if (!user) {
      await this.recordLoginAttempt(undefined, false, undefined, loginDto.username);
      throw new NotFoundException('Invalid credentials.');
    }

    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password_hash);

    if (!isPasswordValid) {
      await this.recordLoginAttempt(user.id, false, undefined, loginDto.username);
      throw new UnauthorizedException('Invalid credentials.');
    }

    user.last_login = new Date();
    await this.userRepository.save(user);

    await this.recordLoginAttempt(user.id, true, undefined, loginDto.username);

    const token = this.jwtService.sign({ userId: user.id });

    return {
      token,
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

  // ... rest of the AuthService code ...
}
