
import { Controller, Put, UseGuards, Param, Body, ParseIntPipe, HttpException, HttpStatus } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UserService } from './users.service';
import { EditUserDto } from './dto/edit-user.dto';

@Controller('api/users')
export class UsersController {
  constructor(private userService: UserService) {}

  @Put('/profile')
  @UseGuards(AuthGuard('jwt'))
  async editUserProfile(
    @Param('id', ParseIntPipe) id: number,
    @Body() editUserDto: EditUserDto
  ) {
    try {
      const updatedUser = await this.userService.editUser(id, editUserDto);
      return {
        status: HttpStatus.OK,
        message: 'Profile updated successfully.',
        user: {
          id: updatedUser.id,
          username: updatedUser.username,
          email: updatedUser.email,
          is_active: updatedUser.is_active,
          last_login: updatedUser.last_login ? updatedUser.last_login.toISOString() : null
        }
      };
    } catch (error: any) {
      throw new HttpException(error.response || 'An unexpected error occurred', error.status || HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
