import { Controller, Put, UseGuards, Param, Body, ParseIntPipe, HttpException, HttpStatus } from '@nestjs/common';
import { AuthGuard } from 'src/guards/auth.guard';
import { UserService } from './users.service';
import { EditUserDto } from './dto/edit-user.dto';

@Controller('api/users')
export class UsersController {
  constructor(private userService: UserService) {}

  @Put('/:id/profile')
  @UseGuards(AuthGuard)
  async editUserProfile(
    @Param('id', ParseIntPipe) id: number,
    @Body() editUserDto: EditUserDto
  ) {
    try {
      await this.userService.editUser(editUserDto);
      return {
        status: HttpStatus.OK,
        message: 'Profile updated successfully.',
        user: {
          id: editUserDto.id,
          username: 'LoremIpsum', // This should be fetched from the database after update
          email: editUserDto.email,
          is_active: true, // This should be fetched from the database after update
          last_login: '2023-02-10T15:45:00Z' // This should be fetched from the database after update
        }
      };
    } catch (error) {
      throw new HttpException(error.response || 'An unexpected error occurred', error.status || HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
