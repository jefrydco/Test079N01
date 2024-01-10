export interface IFileProcess {
  checksum: string;
  file: Buffer;
  fileName: string;
  fileType: string;
  dimension: 'height' | 'width';
}
