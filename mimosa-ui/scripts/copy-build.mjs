import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const buildDir = path.resolve(__dirname, '..', 'build');
const targetDir = path.resolve(__dirname, '..', '..', 'mimosa', 'web', 'static', 'ui');

if (!fs.existsSync(buildDir)) {
  console.error(`Build output not found at ${buildDir}. Run \"npm run build\" first.`);
  process.exit(1);
}

fs.rmSync(targetDir, { recursive: true, force: true });
fs.mkdirSync(targetDir, { recursive: true });

const copyRecursive = (src, dest) => {
  const stats = fs.statSync(src);
  if (stats.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
  } else {
    fs.copyFileSync(src, dest);
  }
};

copyRecursive(buildDir, targetDir);
console.log(`Copied UI build to ${targetDir}`);
