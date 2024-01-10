
import { IsNotEmpty } from 'class-validator';

export class ConfirmEmailDto {
  @IsNotEmpty({ message: 'Verification token is required.' })
  token: string;
}
