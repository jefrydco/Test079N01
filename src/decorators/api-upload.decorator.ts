import { applyDecorators } from '@nestjs/common';
import { ApiConsumes } from '@nestjs/swagger';
import { FormDataRequest, FileSystemStoredFile } from 'nestjs-form-data';

export function ApiUpload() {
  return applyDecorators(
    ApiConsumes('multipart/form-data'),
    FormDataRequest({ storage: FileSystemStoredFile }),
  );
}
