import { ValidateBy, ValidationArguments, ValidationOptions } from 'class-validator';
import { ConfigService } from '@nestjs/config';
import configs from '@configs/index';

const configService = new ConfigService(configs());

export function IsPassword(validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'IsPassword',
      constraints: [configService.get('authentication.passwordPattern', '')],
      validator: {
        validate(value: string, args: ValidationArguments) {
          const passwordPattern = args.constraints[0];
          if (!passwordPattern) return true;

          if (passwordPattern instanceof RegExp) {
            return passwordPattern.test(value);
          }
          const regex = new RegExp(passwordPattern);
          return regex.test(value);
        },

        defaultMessage(validationArguments?: ValidationArguments): string {
          const passwordPattern: string = validationArguments.constraints[0] || '';
          return `Password doesn't match with pattern ${passwordPattern}`;
        },
      },
    },
    validationOptions,
  );
}
