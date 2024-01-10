import { IsNotEmpty, IsEmail, IsString } from 'class-validator';
import { EntityUnique } from 'src/shared/validators/entity-unique.validator';
import { IsPassword } from 'src/shared/validators/is-password.validator';
import { User } from 'src/entities/users.ts';

export class RegisterNewUserDto {
  @EntityUnique(User, 'username', { message: 'Username is already taken' }) // New code specifies the field 'username'
  @IsNotEmpty({ message: 'Username is required' })
  @IsString({ message: 'Username must be a string' })
  username: string;

  @IsPassword({ message: 'Password must be at least 8 characters long.' }) // Existing code uses a custom password validator
  @IsNotEmpty({ message: 'Password is required' }) // New code adds a not empty check
  @IsString({ message: 'Password must be a string' })
  password: string;

  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Invalid email format' })
  @EntityUnique(User, 'email', { message: 'Email is already registered' }) // New code specifies the field 'email'
  email: string;
}
