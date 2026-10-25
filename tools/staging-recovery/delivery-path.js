/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, module, process */
const fs = require('node:fs'),
  path = require('node:path');
function checkDeliveryPath(local = process.env.LOCALAPPDATA) {
  if (!local || !path.isAbsolute(local)) throw Error();
  const comparable = (value) => (process.platform === 'win32' ? value.toLowerCase() : value);
  const root = fs.realpathSync(local);
  if (comparable(path.resolve(local)) !== comparable(root)) throw Error();
  let directory = root;
  for (const component of ['VaultXPay', 'Secrets']) {
    directory = path.join(directory, component);
    try {
      const stat = fs.lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error();
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      fs.mkdirSync(directory, { mode: 0o700 });
    }
    if (comparable(fs.realpathSync(directory)) !== comparable(directory)) throw Error();
  }
  const destination = path.join(directory, 'initial.vaultx-key.json');
  try {
    fs.lstatSync(destination);
  } catch (error) {
    if (error.code === 'ENOENT') return destination;
    throw error;
  }
  throw new Error('Delivery file already exists.');
}
module.exports = { checkDeliveryPath };
