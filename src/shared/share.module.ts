import { Module } from '@nestjs/common';
import { BullModule } from './bull/bull.module';
import { EmailModule } from './email/email.module';
import { FileModule } from './file/file.module';
import { StorageModule } from './storage/storage.module';
import { EntityUniqueValidator } from './validators/entity-unique.validator';

@Module({
  imports: [BullModule, EmailModule, StorageModule, FileModule],
  providers: [EntityUniqueValidator],
})
export class ShareModule {}
