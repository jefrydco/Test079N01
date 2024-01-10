
import { IsNotEmpty, IsEmail, IsString, MinLength } from 'class-validator';
import { EntityUnique } from 'src/shared/validators/entity-unique.validator';
// Removed IsPassword import as we will use MinLength for password validation
import { User } from 'src/entities/users.ts';

export class RegisterNewUserDto {
  @EntityUnique(User, 'username', { message: 'Username is already taken' }) // New code specifies the field 'username'
  @IsNotEmpty({ message: 'Username is required' })
  @IsString({ message: 'Username must be a string' })
  username: string;

  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long.' }) // Use MinLength for password validation
  @IsString({ message: 'Password must be a string' })
  password: string;

  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Invalid email format' })
  @EntityUnique(User, 'email', { message: 'Email is already registered' }) // New code specifies the field 'email'
  email: string;
}
