import { IsNotEmpty, IsEmail, Validate } from 'class-validator';
import { IsEqualTo } from 'src/shared/validators/is-equal-to.validator';

export class EditUserDto {
  @IsNotEmpty({ message: 'ID must not be empty' })
  id: number;

  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsNotEmpty({ message: 'Password must not be empty' })
  password: string;

  @IsNotEmpty({ message: 'Password confirmation must not be empty' })
  @Validate(IsEqualTo, ['password'], {
    message: 'Password confirmation does not match password',
  })
  password_confirmation: string;
}
