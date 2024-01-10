import { Process, Processor } from '@nestjs/bull';
import { Job } from 'bull';
import { ConfigService } from '@nestjs/config';
import sharp from 'sharp';
import { FILE_QUEUE, RESIZE_IMAGE_JOB } from './file.constants';
import { IFileProcess } from './file.type';

@Processor(FILE_QUEUE)
export class FileConsumer {
  constructor(private configService: ConfigService) {}

  @Process(RESIZE_IMAGE_JOB)
  async resizeImage({ data }: Job<IFileProcess>) {
    const imageHeight = this.configService.get('fileConfig.imageSize.height');
    const imageWidth = this.configService.get('fileConfig.imageSize.width');

    let objectResize = {};

    if (data.dimension === 'height') {
      objectResize = {
        height: imageHeight,
        fit: sharp.fit.fill,
      };
    } else {
      objectResize = {
        width: imageWidth,
        fit: sharp.fit.fill,
      };
    }

    sharp(data.file)
      .resize(objectResize)
      .toFormat(data.fileType as any)
      .toBuffer();
  }
}
