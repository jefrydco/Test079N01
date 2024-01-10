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
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { ConfirmEmailDto } from './dtos/confirm-email.dto';
import { LoginDto } from './dto/login.dto'; // Import path is the same in both versions
import { RegisterNewUserDto } from './dtos/register-new-user.dto';
import { RequestPasswordResetDto } from './dtos/request-password-reset.dto';
import { TokenResponseDTO } from './dtos/token-response.dto';
import { RecordLoginAttemptDto } from './dtos/record-login-attempt.dto';

@Controller('api/users') // The base route is the same in both versions
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
  @ApiResponse({ status: 200, description: 'Login successful.' })
  @ApiResponse({ status: 400, description: 'Bad Request: The request was malformed or had invalid parameters.' })
  @ApiResponse({ status: 401, description: 'Unauthorized: The username or password is incorrect.' })
  @ApiResponse({ status: 422, description: 'Unprocessable Entity: The request body or parameters are in the wrong format.' })
  @ApiResponse({ status: 500, description: 'Internal Server Error: An unexpected error occurred on the server.' })
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<TokenResponseDTO | any> { // Return type updated to include 'any' to accommodate both versions
    if (!loginDto.username || !loginDto.password) {
      throw new BadRequestException('Username and password are required.'); // Updated to use 'username' and 'password' from new code
    }
    try {
      const result = await this.authService.login(loginDto.username, loginDto.password); // Updated to pass username and password separately
      return {
        status: HttpStatus.OK,
        message: 'Login successful.',
        access_token: result.token, // Updated to include 'access_token' from existing code
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
      user: result.user, // This line is the same in both versions
    };
  }

  @Post('/:user_id/login_attempts')
  @HttpCode(HttpStatus.CREATED)
  async logLoginAttempt(@Param('user_id') userId: number, @Body() recordLoginAttemptDto: RecordLoginAttemptDto) {
    try {
      await this.authService.recordLoginAttempt(userId, recordLoginAttemptDto.success, recordLoginAttemptDto.ipAddress);
      return { status: HttpStatus.CREATED, message: 'Login attempt logged successfully.' };
    } catch (error) {
      throw error; // Error handling is assumed to be implemented as needed, same in both versions
    }
  }

  @Post('/password-reset-request') // Endpoint updated from new code
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() requestPasswordResetDto: RequestPasswordResetDto): Promise<{ message: string }> {
    try {
      const message = await this.authService.requestPasswordReset(requestPasswordResetDto.email);
      return {
        message,
      };
    } catch (error) {
      throw error;
    }
  }

  // ... rest of the AuthController code ...
}
