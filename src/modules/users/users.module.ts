
import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UserService } from './users.service';
import { UserRepository } from 'src/repositories/users.repository';
import { EntityUniqueValidator } from 'src/shared/validators/entity-unique.validator';

@Module({
  controllers: [UsersController],
  providers: [
    UserService,
    UserRepository,
    EntityUniqueValidator,
  ],
  exports: [UserService],
})
export class UsersModule {}
