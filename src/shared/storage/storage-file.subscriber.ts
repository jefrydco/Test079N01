import { Injectable } from '@nestjs/common';
import { EventSubscriber, EntitySubscriberInterface, DataSource, LoadEvent } from 'typeorm';
import { StorageFile } from '@entities/storage_files';
import { StorageService, DriverType } from '@codebrew/nestjs-storage';
import { ConfigService } from '@nestjs/config';

@EventSubscriber()
@Injectable()
export class StorageFileSubscriber implements EntitySubscriberInterface<StorageFile> {
  constructor(
    dataSource: DataSource,
    private readonly storageService: StorageService,
    private readonly configService: ConfigService,
  ) {
    dataSource.subscribers.push(this);
  }

  listenTo() {
    return StorageFile;
  }

  async afterLoad(entity: StorageFile): Promise<void> {
    const storageDisk = this.storageService.getDisk(entity.disk || '');
    if (entity.disk === DriverType.S3) {
      const signedUrlResponse = await storageDisk.getSignedUrl(entity.file_path);
      entity.url = signedUrlResponse.signedUrl;
    } else {
      entity.url = `${this.configService.get('storage.disks.local.config.publicUrl')}/${
        entity.file_path
      }`;
    }
  }
}
