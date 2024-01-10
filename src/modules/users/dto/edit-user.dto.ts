
import { IsNotEmpty, IsEmail, IsInt } from 'class-validator';

export class EditUserDto {
  @IsNotEmpty({ message: 'ID must not be empty' })
  @IsInt({ message: 'Invalid user ID format.' })
  id: number;

  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;
}
