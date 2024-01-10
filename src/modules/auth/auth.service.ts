import {
  BadRequestException,
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { encryptPassword } from 'src/utils/transform';
import { EmailService } from 'src/shared/email/email.service';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { RegisterNewUserDto } from './dtos/register-new-user.dto';
import { PasswordResetRepository } from 'src/repositories/password-reset.repository';
import { PasswordReset } from 'src/entities/password_resets';

export class RegisterUserResponseDto {
  success: boolean;
  message: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
    private readonly passwordResetRepository: PasswordResetRepository,
  ) {}

  async registerNewUser(registerUserDto: RegisterNewUserDto): Promise<RegisterUserResponseDto> {
    const { username, password, email } = registerUserDto;

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

  async requestPasswordReset(email: string): Promise<{ status: number; message: string }> {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      throw new NotFoundException('Email does not exist.');
    }

    const token = crypto.randomBytes(16).toString('hex');
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

    const passwordReset = new PasswordReset();
    passwordReset.token = token;
    passwordReset.expires_at = expiresAt;
    passwordReset.user = user;

    await this.passwordResetRepository.save(passwordReset);

    await this.emailService.sendPasswordResetEmail(user.email, token);

    return { status: 200, message: 'Password reset link has been sent to your email.' };
  }

  // ... rest of the AuthService code ...
}
