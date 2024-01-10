
import { Injectable, NotFoundException, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthService } from 'src/modules/auth/auth.service'; // Added AuthService import
import { Repository } from 'typeorm';
import { UpdateShopDto } from './dto/update-shop.dto';
import { Shop } from 'src/entities/shop.entity'; // Assuming the entity exists based on ERD information

@Injectable()
export class ShopsService {
  constructor(
    private authService: AuthService, // Injected AuthService
    @InjectRepository(Shop)
    private shopsRepository: Repository<Shop>,
  ) {}

  async updateShop(updateShopDto: UpdateShopDto): Promise<string> {
    // Validate input
    if (!updateShopDto.id || !updateShopDto.name || !updateShopDto.address) {
      throw new BadRequestException('Shop ID, name, and address are required.');
    }

    const shop = await this.shopsRepository.findOneBy({ id: updateShopDto.id });
    if (!shop) {
      throw new NotFoundException(`Shop with ID ${updateShopDto.id} not found`);
    }

    // Check permissions (assuming there's a method in AuthService to check permissions)
    if (!await this.authService.hasPermissionToUpdateShop(updateShopDto.id)) {
      throw new UnauthorizedException('You do not have permission to update this shop.');
    }

    await this.shopsRepository.update(updateShopDto.id, {
      name: updateShopDto.name,
      address: updateShopDto.address,
      // Update the "updated_at" field to the current datetime
      updated_at: new Date(),
    });

    return 'Shop information has been updated successfully.';
  }
}
