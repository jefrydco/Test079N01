import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { StorageService, DriverType } from '@codebrew/nestjs-storage';
import { StorageFile } from '@entities/storage_files';
import { FileSystemStoredFile } from 'nestjs-form-data';
import { readFileSync } from 'fs';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { extname } from 'path';
import { snakeCase } from 'lodash';
import { lookup } from 'mime-types';
import { AmazonWebServicesS3Storage } from '@slynova/flydrive-s3';
import * as md5File from 'md5-file';

@Injectable()
export class UploadService {
  constructor(
    @InjectRepository(StorageFile) private readonly repository: Repository<StorageFile>,
    private readonly storageService: StorageService,
    private readonly configService: ConfigService,
  ) {
    this.storageService.registerDriver(DriverType.S3, AmazonWebServicesS3Storage);
  }

  private get defaultDisk() {
    return this.configService.get('storage.default');
  }

  async uploadFile(
    file: FileSystemStoredFile,
    folderPath?: string,
    disk?: string,
    uploader_id?: number,
  ) {
    if (!file) return null;
    const mimeType = lookup(file.path);
    const checksum = await md5File(file.path);
    const fileName = this._parseFileName(file.originalName);
    const storageDisk = this._getDisk(disk);
    const filePath = !folderPath ? fileName : `${folderPath}/${fileName}`;

    let fileObj: Partial<StorageFile> = {
      checksum: checksum,
      file_path: filePath,
      origin_name: file.originalName,
      disk: disk || this.defaultDisk,
      mime_type: mimeType,
      size: file.size,
    };

    if (uploader_id) {
      fileObj = {
        ...fileObj,
        uploader_id,
      };
    }

    try {
      const fileStorage = this.repository.create(fileObj);
      const result = this.repository.save(fileStorage);
      await storageDisk.put(filePath, readFileSync(file.path));
      return result;
    } catch (e) {
      throw new InternalServerErrorException(e);
    }
  }

  async uploadFiles(files: FileSystemStoredFile[], folderPath?: string, disk?: string) {
    if (!files) return null;
    return await Promise.all(files.map((file) => this.uploadFile(file, folderPath, disk)));
  }

  async getFiledByFilePath(filePath: string) {
    return await this.repository.findOneBy({ file_path: filePath });
  }

  async validateUniqueChecksum(checksum: string) {
    if (await this.repository.findOneBy({ checksum })) {
      throw new InternalServerErrorException('File already exists');
    }
  }

  private _getDisk(disk?: string) {
    return this.storageService.getDisk(disk || '');
  }

  private _parseFileName(originName: string) {
    const ext = extname(originName);
    return `${snakeCase(originName.replace(`${ext}`, ''))}_${Date.now()}${ext}`;
  }
}
