import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UpdateShopDto } from './dto/update-shop.dto';
import { Shop } from 'src/entities/shop.entity'; // Assuming the entity exists based on ERD information

@Injectable()
export class ShopsService {
  constructor(
    @InjectRepository(Shop)
    private shopsRepository: Repository<Shop>,
  ) {}

  async updateShop(updateShopDto: UpdateShopDto): Promise<string> {
    const shop = await this.shopsRepository.findOneBy({ id: updateShopDto.id });
    if (!shop) {
      throw new NotFoundException(`Shop with ID ${updateShopDto.id} not found`);
    }
    await this.shopsRepository.update(updateShopDto.id, {
      name: updateShopDto.name,
      address: updateShopDto.address,
    });
    return 'Shop information has been updated successfully.';
  }
}
