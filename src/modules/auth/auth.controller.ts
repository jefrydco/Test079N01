import { Body, Controller, HttpCode, HttpStatus, Post, BadRequestException, UnauthorizedException, Param } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto'; // Assuming this is the correct path after resolving the conflict
import { RequestPasswordResetDto } from './dtos/request-password-reset.dto';
import { TokenResponseDTO } from './dtos/token-response.dto';
import { RecordLoginAttemptDto } from './dtos/record-login-attempt.dto';

@Controller('api/users')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<TokenResponseDTO> {
    if (!loginDto.username || !loginDto.password) {
      throw new BadRequestException('Username and password are required.');
    }
    try {
      const result = await this.authService.login(loginDto);
      return {
        token: result.token,
        message: 'Login successful',
      };
    } catch (error) {
      if (error.status === HttpStatus.UNAUTHORIZED) {
        throw new UnauthorizedException('Invalid credentials.');
      }
      throw error;
    }
  }

  @Post('/:user_id/login_attempts')
  @HttpCode(HttpStatus.CREATED)
  async logLoginAttempt(@Param('user_id') userId: number, @Body() recordLoginAttemptDto: RecordLoginAttemptDto) {
    try {
      await this.authService.recordLoginAttempt(userId, recordLoginAttemptDto.success, recordLoginAttemptDto.ipAddress);
      return { status: HttpStatus.CREATED, message: 'Login attempt logged successfully.' };
    } catch (error) {
      // Error handling based on the type of error
      // The specific error handling is not provided in the patch, so it's assumed to be implemented as needed.
      throw error; // Re-throw the error for now as no specific error handling is provided
    }
  }

  @Post('/password-reset')
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() requestPasswordResetDto: RequestPasswordResetDto): Promise<{ message: string }> {
    const message = await this.authService.requestPasswordReset(requestPasswordResetDto.email);
    return {
      message,
    };
  }

  // ... rest of the AuthController code ...
}
