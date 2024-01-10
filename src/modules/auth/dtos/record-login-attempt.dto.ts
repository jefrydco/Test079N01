import { IsNotEmpty, IsBoolean, IsIP, IsInt } from 'class-validator';

export class RecordLoginAttemptDto {
  @IsInt()
  @IsNotEmpty({ message: 'User ID must not be empty' })
  userId: number;

  @IsBoolean()
  @IsNotEmpty({ message: 'Success status must not be empty' })
  success: boolean;

  @IsIP()
  @IsNotEmpty({ message: 'IP address must not be empty' })
  ipAddress: string;
}
