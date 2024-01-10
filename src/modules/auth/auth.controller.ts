import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
  Param,
  HttpException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { ConfirmEmailDto } from './dtos/confirm-email.dto';
import { LoginDto } from './dtos/login.dto';
import { RegisterNewUserDto } from './dtos/register-new-user.dto';
import { RequestPasswordResetDto } from './dtos/request-password-reset.dto';
import { TokenResponseDTO } from './dtos/token-response.dto';
import { RecordLoginAttemptDto } from './dtos/record-login-attempt.dto';

@Controller('api/users')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/confirm-email')
  @HttpCode(HttpStatus.OK)
  async confirmEmail(@Body() confirmEmailDto: ConfirmEmailDto): Promise<{ status: number; message: string }> {
    try {
      const result = await this.authService.confirmEmail(confirmEmailDto.token);
      return {
        status: HttpStatus.OK,
        message: result,
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error.response);
      } else if (error instanceof NotFoundException) {
        throw new NotFoundException(error.response);
      } else {
        throw new Error('Internal Server Error');
      }
    }
  }

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
      if (error instanceof UnauthorizedException || error.status === HttpStatus.UNAUTHORIZED) {
        throw new UnauthorizedException('Invalid credentials.');
      }
      throw error;
    }
  }

  @Post('/register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerNewUserDto: RegisterNewUserDto): Promise<{ status: number; message: string; user?: any }> {
    const result = await this.authService.registerNewUser(registerNewUserDto);
    if (!result.success) {
      throw new HttpException(result.message, HttpStatus.CONFLICT);
    }
    return {
      status: HttpStatus.CREATED,
      message: result.message,
      user: result.user, // Added from new code to include user data in the response
    };
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
