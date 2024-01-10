import { IsNotEmpty, IsInt } from 'class-validator';

export class UpdateShopDto {
  @IsInt()
  @IsNotEmpty({ message: 'Shop ID must not be empty' })
  id: number;

  @IsNotEmpty({ message: 'Shop name must not be empty' })
  name: string;

  @IsNotEmpty({ message: 'Shop address must not be empty' })
  address: string;
}
