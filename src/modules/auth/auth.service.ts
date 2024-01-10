import { Injectable, BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/entities/users';
import { LoginAttempt } from 'src/entities/login_attempts';

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly loginAttemptRepository: LoginAttemptRepository,
    private readonly jwtService: JwtService
  ) {}

  async login(username: string, password: string): Promise<{ token: string; message: string }> {
    if (!username || !password) {
      throw new BadRequestException('Username and password are required.');
    }

    const user = await this.userRepository.findOne({ where: { username } });

    if (!user) {
      await this.logLoginAttempt(username, false);
      throw new NotFoundException('Invalid credentials.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      await this.logLoginAttempt(username, false, user.id);
      throw new UnauthorizedException('Invalid credentials.');
    }

    user.last_login = new Date();
    await this.userRepository.save(user);

    await this.logLoginAttempt(username, true, user.id);

    const token = this.jwtService.sign({ userId: user.id });

    return {
      token,
      message: 'Login successful.'
    };
  }

  private async logLoginAttempt(username: string, success: boolean, userId?: number): Promise<void> {
    const loginAttempt = new LoginAttempt();
    loginAttempt.attempt_time = new Date();
    loginAttempt.success = success;
    loginAttempt.user_id = userId;
    await this.loginAttemptRepository.save(loginAttempt);
  }
}
