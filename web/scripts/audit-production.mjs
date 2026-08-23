import { execFileSync } from 'node:child_process';

let output;
try {
  output = execFileSync('npm', ['audit', '--omit=dev', '--json'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  });
} catch (error) {
  if (!error.stdout) throw error;
  output = error.stdout.toString();
}

const report = JSON.parse(output);
const blocking = [];

for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
  if (!['high', 'critical'].includes(vulnerability.severity)) continue;
  for (const advisory of vulnerability.via ?? []) {
    if (typeof advisory === 'string') continue;
    blocking.push(`${vulnerability.name}: ${advisory.title} (${advisory.source})`);
  }
}

if (blocking.length > 0) {
  console.error(`Blocking production vulnerabilities:\n${blocking.join('\n')}`);
  process.exit(1);
}

console.log('No high or critical production vulnerabilities.');
