import { IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty({ message: 'Username should not be empty' })
  username: string;

  @IsNotEmpty({ message: 'Password should not be empty' })
  password: string;

  constructor(username: string, password: string) {
    this.username = username; this.password = password;
  }
}
