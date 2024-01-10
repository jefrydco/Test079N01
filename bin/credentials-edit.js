
require('dotenv').config();
const fs = require('fs');
const { spawn } = require('child_process');
const Vault = require('node-credentials').Vault
const commandLineArgs = require('command-line-args')

const editContentInEditor = (content) => {
  const editor = process.env.EDITOR || 'vi';

  const uuid = new Date().getTime();
  const tempFileName = `/tmp/${uuid}`;
  fs.writeFileSync(tempFileName, content);

  const shell = spawn(editor, [tempFileName], { stdio: 'inherit' });

  return new Promise((resolve, reject) => {
    shell.on('close', (code) => {
      const tmpContent = fs.readFileSync(tempFileName, 'utf-8');
      resolve(tmpContent);
      fs.unlinkSync(tempFileName);
    });
  });
};


const edit = async () => {   
  const optionDefinitions = [
    { name: 'environment', alias: 'e', type: String  },
    { name: 'key', alias: 'k', type: String },    
  ]
  const options = commandLineArgs(optionDefinitions)
  
  const vault = new Vault({ credentialsFilePath: `src/credentials/${options.environment || process.env.APP_ENV}.yaml`})
  const masterKey = options.key || vault.getMasterKey();

  try {
    const [content, iv] = vault.decryptFnc(masterKey, fs.readFileSync(vault.credentialsFilePath, 'utf-8'));
    const mewContent = await editContentInEditor(content);
    const encryptedContent = await vault.encryptFnc(masterKey, mewContent, iv);
    fs.writeFileSync(vault.credentialsFilePath, encryptedContent);
  } catch (err) {
    console.error(err);
  }
}

edit()