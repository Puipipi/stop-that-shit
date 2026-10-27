const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const target = path.join(root, 'codex-plugin');
const entries = ['.codex-plugin/plugin.json', 'hooks/codex-hooks.json', 'hooks/stop-that-shit.cjs', 'src', 'package.json', 'LICENSE', 'skills', 'assets/stop-icon.svg'];
function files(base, relative = '') {
  const full = path.join(base, relative);
  return fs.statSync(full).isDirectory()
    ? fs.readdirSync(full).sort().flatMap(name => files(base, path.join(relative, name)))
    : [relative];
}
const expected = entries.flatMap(entry => files(root, entry)).map(file => file.replaceAll(path.sep, '/')).sort();
if (process.argv.includes('--check')) {
  const actual = fs.existsSync(target) ? files(target).map(file => file.replaceAll(path.sep, '/')).sort() : [];
  if (JSON.stringify(expected) !== JSON.stringify(actual) || expected.some(file => !fs.readFileSync(path.join(root, file)).equals(fs.readFileSync(path.join(target, file))))) {
    console.error('Codex plugin bundle is out of sync; run npm run codex:build');
    process.exitCode = 1;
  } else console.log(`PASS Codex plugin bundle (${expected.length} files)`);
} else {
  fs.rmSync(target, {recursive: true, force: true});
  for (const file of expected) {
    const destination = path.join(target, file);
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.copyFileSync(path.join(root, file), destination);
  }
  console.log(`Built Codex plugin bundle (${expected.length} files)`);
}
