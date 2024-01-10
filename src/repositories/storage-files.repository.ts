import { Injectable } from '@nestjs/common';
import { BaseRepository } from 'src/shared/base.repository';
import { StorageFile } from 'src/entities/storage_files';

@Injectable()
export class AccessTokenRepository extends BaseRepository<StorageFile> {}
