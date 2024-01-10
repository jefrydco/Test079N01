 {
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

// Additional DTO import
import { RegisterNewUserDto } from './dtos/register-new-user.dto'; // Added import for RegisterNewUserDto
import { JwtPayload } from './interfaces/jwt-payload.interface'; // Assume JwtPayload interface exists

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly loginAttemptRepository: LoginAttemptRepository,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
    private readonly emailVerificationRepository: EmailVerificationRepository,
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
      throw a NotFoundException('Invalid confirmation token.');
    }

    user.is_active = true;
    user.updated_at = new Date();
    user.emailConfirmationToken = null;

    await this.userRepository.save(user);

    await this.emailService.sendConfirmationEmail({ email: user.email, token });

    return 'Email has been successfully confirmed.';
  }

  async login(loginDto: LoginDto): Promise<{ status: number; message: string; access_token: string }> {
    const { email, password } = loginDto;

    // Validate email format
    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email format.');
    }

    // Validate password is not blank
    if (!password) {
      throw new BadRequestException('Password is required.');
    }

    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Incorrect email or password.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Incorrect email or password.');
    }

    const payload: JwtPayload = { userId: user.id };
    const accessToken = this.jwtService.sign(payload);
    return { status: 200, message: 'Login successful.', access_token: accessToken };
  }

  // ... rest of the AuthService code ...
}
