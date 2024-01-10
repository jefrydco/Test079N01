import { Body, Controller, HttpCode, HttpStatus, Post, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto'; // Assuming this is the correct path after resolving the conflict
import { RequestPasswordResetDto } from './dtos/request-password-reset.dto';
import { TokenResponseDTO } from './dtos/token-response.dto';

@Controller()
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/api/users/login') // Updated endpoint to match the new code
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<TokenResponseDTO> {
    if (!loginDto.username || !loginDto.password) {
      throw new BadRequestException('Username and password are required.');
    }
    try {
      const result = await this.authService.login(loginDto.username, loginDto.password);
      return new TokenResponseDTO(result.token, 'Login successful.');
    } catch (error) {
      if (error.status === HttpStatus.UNAUTHORIZED) {
        throw new UnauthorizedException('Invalid credentials.');
      }
      throw error;
    }
  }

  @Post('/password-reset') // Keeping the existing password reset endpoint
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() requestPasswordResetDto: RequestPasswordResetDto): Promise<{ message: string }> {
    const message = await this.authService.requestPasswordReset(requestPasswordResetDto.email);
    return {
      message,
    };
  }
}
