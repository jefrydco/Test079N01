import {
  Controller,
  Body,
  Param,
  Put,
  UseGuards,
  ParseIntPipe,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { UpdateShopDto } from './dto/update-shop.dto';
import { ShopsService } from './shops.service';
import { AuthGuard } from 'src/guards/auth.guard';

@Controller('api/shops')
export class ShopsController {
  constructor(private readonly shopsService: ShopsService) {}

  @Put(':id')
  @UseGuards(AuthGuard)
  async updateShop(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateShopDto: UpdateShopDto,
  ) {
    const updatedShop = await this.shopsService.updateShop({ ...updateShopDto, id });
    return { status: HttpStatus.OK, message: 'Shop information updated successfully.', shop: updatedShop };
  }
}
