
import { ClassConstructor, plainToClass } from 'class-transformer';
import * as bcrypt from 'bcryptjs';

export function serialize<T, O>(transformClass: ClassConstructor<T>, plainObject: O) {
  return plainToClass(transformClass, plainObject, { excludeExtraneousValues: true });
}

export function serializeArray<T, O>(transformClass: ClassConstructor<T>, plainArray: O[]) {
  return plainArray.map((object) =>
    plainToClass(transformClass, object, { excludeExtraneousValues: true }),
  );
}

export async function encryptPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}
