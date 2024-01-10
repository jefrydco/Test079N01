import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import { FILE_QUEUE } from './file.constants';
import { FileService } from './file.service';
import { FileConsumer } from './file.consumer';

@Module({
  imports: [BullModule.registerQueue({ name: FILE_QUEUE })],
  providers: [FileService, FileConsumer],
  exports: [FileService],
})
export class FileModule {}
