import { Injectable } from '@nestjs/common';
import { BaseRepository } from 'src/shared/base.repository';
import { AccessToken } from 'src/entities/access_tokens';

@Injectable()
export class AccessTokenRepository extends BaseRepository<AccessToken> {}
