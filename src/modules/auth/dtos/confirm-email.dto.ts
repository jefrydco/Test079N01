import { IsNotEmpty } from 'class-validator';

export class ConfirmEmailDto {
  @IsNotEmpty({ message: 'Token should not be empty' })
  token: string;

  constructor(token: string) {
    this.token = token;
  }
}
