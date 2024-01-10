import { InjectQueue } from '@nestjs/bull';
import { Injectable, Logger, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Queue } from 'bull';
import { Cache } from 'cache-manager';
import { FILE_QUEUE, RESIZE_IMAGE_JOB } from './file.constants';
import { IFileProcess } from './file.type';

@Injectable()
export class FileService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    @InjectQueue(FILE_QUEUE) private readonly fileQueue: Queue,
  ) {}

  private logger = new Logger(FileService.name);

  async resizeImage(file: IFileProcess) {
    try {
      const getKey = await this.cacheManager.get(`${file.checksum}`);

      if (getKey) return;

      await this.cacheManager.set(`${file.checksum}`, 'PROCESSING_RESIZE');

      await this.fileQueue.add(RESIZE_IMAGE_JOB, file);
      return true;
    } catch (e) {
      this.logger.error('An error occur while adding send mail job', e);
      return false;
    }
  }
}
