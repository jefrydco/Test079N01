import { Controller, Get, Query } from '@nestjs/common';
import { UploadService } from './upload.service';
import { ApiTags } from '@nestjs/swagger';

@Controller()
@ApiTags('Upload')
export class UploadController {
  constructor(private readonly uploadService: UploadService) {}

  @Get('api/get_file_by_path')
  async getUserIdFromFile(@Query() query: { file: string }) {
    const filePath = query.file;

    const file = await this.uploadService.getFiledByFilePath(filePath);

    return file;
  }
}
