
import { IsNotEmpty, IsEmail } from 'class-validator';

export class ConfirmEmailDto {
  @IsEmail({}, { message: 'Invalid email format.' })
  email: string;

  @IsNotEmpty({ message: 'Confirmation code is required.' })
  confirmation_code: string;

  @IsNotEmpty({ message: 'Token should not be empty' })
  token: string;

  constructor(token: string) {
    this.token = token;
  }
}
