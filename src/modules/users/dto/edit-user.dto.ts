
import { IsNotEmpty, IsEmail, IsInt } from 'class-validator';
import { EntityUnique } from 'src/shared/validators/entity-unique.validator';
import { User } from 'src/entities/users.ts';

export class EditUserDto {
  @IsNotEmpty({ message: 'ID must not be empty' })
  @IsInt({ message: 'Invalid user ID format.' })
  id: number;

  @IsNotEmpty({ message: 'Username is required' })
  @EntityUnique(User, { message: 'Username is already taken' })
  username: string;

  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;
}
