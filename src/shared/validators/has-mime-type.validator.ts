import { ValidateBy, ValidationArguments, ValidationOptions } from 'class-validator';
import { isFile } from 'nestjs-form-data';

type FileSystemStoredFileCustom = {
  originalName: string;
  encoding: string;
  busBoyMimeType: string;
  path: string;
  size: number;
  fileType: {
    ext: string;
    mime: string;
  };
};

export function HasMimeType(
  allowedMimeTypes: string[] | string,
  validationOptions?: ValidationOptions,
): PropertyDecorator {
  return ValidateBy(
    {
      name: 'HasMimeType',
      constraints: [allowedMimeTypes],
      validator: {
        validate(value: FileSystemStoredFileCustom, args: ValidationArguments) {
          const allowedMimeTypes: string[] = args.constraints[0];
          if (isFile(value)) {
            return allowedMimeTypes.some((mime) => value.busBoyMimeType.includes(mime));
          }
          return false;
        },

        defaultMessage(validationArguments?: ValidationArguments): string {
          const allowedMimeTypes: string[] = validationArguments.constraints[0] || [];
          return `File must be of one of the types ${allowedMimeTypes.join(', ')}`;
        },
      },
    },
    validationOptions,
  );
}
