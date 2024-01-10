import { IsNotEmpty, IsEmail, IsString } from 'class-validator';
import { EntityUnique } from 'src/shared/validators/entity-unique.validator';
import { User } from 'src/entities/users.ts';

export class RegisterNewUserDto {
  @EntityUnique(User, { message: 'Username is already taken' })
  @IsNotEmpty({ message: 'Username is required' })
  @IsString({ message: 'Username must be a string' })
  username: string;

  @IsNotEmpty({ message: 'Password is required' })
  @IsString({ message: 'Password must be a string' })
  password: string;

  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Invalid email format' })
  @EntityUnique(User, { message: 'Email is already registered' })
  email: string;
}
