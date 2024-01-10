
import { IsNotEmpty, IsEmail } from 'class-validator';
import { IsPassword } from 'src/shared/validators/is-password.validator';

export class LoginDto {
  @IsEmail({}, { message: "Invalid email format." })
  email: string;

  @IsNotEmpty({ message: "Password is required." })
  @IsPassword()
  password: string;
}
