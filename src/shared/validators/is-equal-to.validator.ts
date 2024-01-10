 { registerDecorator, ValidationArguments, ValidationOptions } from 'class-validator';

export function IsEqualTo<T>(property: keyof T, validationOptions?: ValidationOptions) {
  return (object: any, propertyName: string) => {
    registerDecorator({
      name: 'IsEqualTo',
      target: object.constructor,
      propertyName,
      constraints: [property],
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          const relatedPropertyName: keyof T = args.constraints[0];
          const relatedValue = (args.object as T)[relatedPropertyName];
          return value === relatedValue;
        },

        defaultMessage(args: ValidationArguments) {
          const relatedPropertyName: keyof T = args.constraints[0];
          return `${propertyName} must match ${relatedPropertyName} exactly`;
        },
      },
    });
  };
}
