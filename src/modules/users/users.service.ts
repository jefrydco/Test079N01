
import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { UserRepository } from '../../repositories/users.repository';
import { EditUserDto } from './dto/edit-user.dto';
import { User } from '../../entities/users';
import { EntityUniqueValidator } from '../../shared/validators/entity-unique.validator';

@Injectable()
export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly entityUniqueValidator: EntityUniqueValidator,
  ) {}

  async editUser(editUserDto: EditUserDto): Promise<any> {
    const { id, email } = editUserDto;

    if (!Number.isInteger(id)) {
      throw new BadRequestException('Invalid user ID format.');
    }

    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    const isEmailUnique = await this.entityUniqueValidator.validate(email, {
      constraints: [this.userRepository.target],
      property: 'email',
      object: { id },
    });

    if (!isEmailUnique) {
      throw new BadRequestException('The email is already registered.');
    }

    await this.userRepository.update(id, { email });

    const updatedUser = await this.userRepository.findOne({ where: { id } });

    return {
      status: 200,
      message: 'Profile updated successfully.',
      user: updatedUser,
    };
  }
}
