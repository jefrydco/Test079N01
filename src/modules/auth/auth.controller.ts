import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { RequestPasswordResetDto } from './dtos/request-password-reset.dto';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { TokenResponseDTO } from './dtos/token-response.dto';

@Controller()
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<TokenResponseDTO> {
    const result = await this.authService.login(loginDto);
    return {
      token: result.token,
      message: 'Login successful',
    };
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