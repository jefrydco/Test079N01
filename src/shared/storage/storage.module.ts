import { StorageModule as NestStorageModule } from '@codebrew/nestjs-storage';
import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { StorageConfig } from '@configs/config.interface';
import { StorageFile } from '@entities/storage_files';
import { StorageFileSubscriber } from './storage-file.subscriber';
import { UploadService } from './upload.service';
import { UploadController } from './upload.controller';

@Global()
@Module({
  imports: [
    TypeOrmModule.forFeature([StorageFile]),
    NestStorageModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configSerivce: ConfigService) => {
        return configSerivce.get<StorageConfig>('storage');
      },
    }),
  ],
  controllers: [UploadController],
  providers: [UploadService, StorageFileSubscriber],
  exports: [UploadService],
})
export class StorageModule {}
