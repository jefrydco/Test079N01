import { IsNotEmpty, IsBoolean, IsIP, IsInt } from 'class-validator';

export class RecordLoginAttemptDto {
  @IsInt()
  @IsNotEmpty({ message: 'User ID is required.' }) // Use the new message for better user feedback
  userId: number;

  @IsBoolean()
  @IsNotEmpty({ message: 'Success status is required.' }) // Use the new message for better user feedback
  success: boolean;

  @IsIP()
  @IsNotEmpty({ message: 'IP address is required.' }) // Use the new message for better user feedback
  ipAddress: string;
}
