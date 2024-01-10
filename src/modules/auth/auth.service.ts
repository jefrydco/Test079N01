import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
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
    private readonly jwtService: JwtService // Keep JwtService from existing code
  ) {}

  async login(username: string, password: string): Promise<{ token: string; message: string }> {
    if (!username || !password) {
      throw new BadRequestException('Username and password are required.');
    }

    const user = await this.userRepository.findOne({ where: { username } });

    if (!user) {
      await this.recordLoginAttempt(undefined, false, undefined, username); // Modified to use the new method
      throw new NotFoundException('Invalid credentials.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      await this.recordLoginAttempt(user.id, false, undefined, username); // Modified to use the new method
      throw new UnauthorizedException('Invalid credentials.');
    }

    user.last_login = new Date();
    await this.userRepository.save(user);

    await this.recordLoginAttempt(user.id, true, undefined, username); // Modified to use the new method

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
      // If username is provided but not userId, we attempt to find the user by username
      const user = await this.userRepository.findOne({ where: { username } });
      if (!user) {
        throw new NotFoundException('User does not exist.');
      }
      userId = user.id; // Set the userId for the login attempt
    }

    const loginAttempt = new LoginAttempt();
    loginAttempt.user_id = userId;
    loginAttempt.attempt_time = new Date();
    loginAttempt.success = success;
    loginAttempt.ip_address = ipAddress || ''; // Use empty string if ipAddress is not provided
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

  // ... rest of the AuthService code ...
}
