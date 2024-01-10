import { IsNotEmpty, IsBoolean, IsIP, IsInt } from 'class-validator';

export class RecordLoginAttemptDto {
  @IsInt({ message: 'Invalid user ID format.' }) // Updated message from new code
  @IsNotEmpty({ message: 'User ID must not be empty' }) // Updated message from new code
  userId: number;

  @IsBoolean()
  @IsNotEmpty({ message: 'Success status must not be empty' }) // Updated message from new code
  success: boolean;

  @IsIP({ message: 'IP address is required.' }) // Kept the existing message as it is more appropriate
  @IsNotEmpty({ message: 'IP address must not be empty' }) // Updated message from new code
  ipAddress: string;
}
