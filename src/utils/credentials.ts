import { existsSync } from 'fs';
import { Vault } from 'node-credentials';

export const getCredentials = (env: string) => {
  try {
    // If project is not build yet, get credentials from source file
    const credentialsFilePath = existsSync(`dist/credentials/${env}.yaml`)
      ? `dist/credentials/${env}.yaml`
      : `src/credentials/${env}.yaml`;
    const vault = new Vault({ credentialsFilePath });
    return vault.credentials;
  } catch (e) {
    // Just log error and return empty to avoid blocking development in case missing credentials key
    console.log(e.message);
    return {};
  }
};
