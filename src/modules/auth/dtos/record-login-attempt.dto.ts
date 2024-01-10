import { IsNotEmpty, IsBoolean, IsIP, IsInt } from 'class-validator';

export class RecordLoginAttemptDto {
  @IsInt()
  @IsNotEmpty()
  userId: number;

  @IsBoolean()
  @IsNotEmpty()
  success: boolean;

  @IsIP()
  @IsNotEmpty()
  ipAddress: string;
}
