import { Injectable, BadRequestException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { EditUserDto } from './dto/edit-user.dto';
import * as bcrypt from 'bcryptjs';
import { EntityUniqueValidator } from 'src/shared/validators/entity-unique.validator';

@Injectable()
export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly entityUniqueValidator: EntityUniqueValidator,
  ) {}

  async editUser(editUserDto: EditUserDto): Promise<string> {
    const { id, email, password, password_confirmation } = editUserDto;

    if (!email || !password || !password_confirmation) {
      throw new BadRequestException('Email, password, and password confirmation are required.');
    }

    if (password !== password_confirmation) {
      throw new BadRequestException('Passwords do not match.');
    }

    const isEmailUnique = await this.entityUniqueValidator.validate(email, {
      constraints: [this.userRepository.target],
      property: 'email',
      object: { id },
    });

    if (!isEmailUnique) {
      throw new BadRequestException('The email is already registered.');
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await this.userRepository.update(id, { email, password_hash: passwordHash });

    return 'User profile has been updated successfully.';
  }
}
