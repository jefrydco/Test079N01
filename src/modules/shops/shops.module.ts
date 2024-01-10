import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Shop } from 'src/entities/shop.entity'; // Import based on ERD information
import { ShopsService } from './shops.service';
import { ShopsController } from './shops.controller'; // Assuming the controller exists based on the requirement

@Module({
  imports: [TypeOrmModule.forFeature([Shop])],
  providers: [ShopsService],
  controllers: [ShopsController],
})
export class ShopsModule {}