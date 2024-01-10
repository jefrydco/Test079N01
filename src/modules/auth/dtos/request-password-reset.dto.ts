import { IsNotEmpty, IsEmail } from 'class-validator';

export class RequestPasswordResetDto {
  @IsNotEmpty({
    message: 'Email is required'
  })
  @IsEmail({}, {
    message: 'Invalid email format'
  })
  email: string;
}
