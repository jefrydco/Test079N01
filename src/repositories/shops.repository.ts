import { EntityRepository, Repository } from 'typeorm';
import { Shop } from '../entities/shop.entity';
import { UpdateShopDto } from '../dtos/update-shop.dto';

@EntityRepository(Shop)
export class ShopsRepository extends Repository<Shop> {

  async findShopById(id: number): Promise<Shop | null> {
    return await this.findOneBy({ id });
  }

  async updateShopInformation(updateShopDto: UpdateShopDto): Promise<string> {
    const { id, name, address } = updateShopDto;

    if (!id || !name || !address) {
      throw new Error('Validation failed: id, name, and address are required.');
    }

    const shop = await this.findShopById(id);
    if (!shop) {
      throw new Error('Invalid shop id.');
    }

    await this.update(id, { name, address });
    return 'Shop information has been updated successfully.';
  }
}
