import { createInterface } from 'node:readline';

export function createCLI({ noPause = false } = {}) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });

  function pause() {
    if (noPause) return Promise.resolve();
    return new Promise(resolve => {
      rl.question('                                                ▸ press ENTER ◂', () => resolve());
    });
  }

  function getChoice(max) {
    return new Promise(resolve => {
      const ask = () => {
        rl.question(`                                                    ▸ pick 1-${max} ◂ `, answer => {
          const n = parseInt(answer, 10);
          if (n >= 1 && n <= max) resolve(n);
          else ask();
        });
      };
      ask();
    });
  }

  async function explore(prompt, scenarios) {
    const visited = new Set();

    if (noPause) {
      for (let i = 0; i < scenarios.length; i++) {
        console.log(`\n  ── [${i + 1}] ${scenarios[i].name} ──\n`);
        await scenarios[i].fn();
      }
      return;
    }

    while (true) {
      console.log(`\n  ❓ ${prompt}\n`);
      for (let i = 0; i < scenarios.length; i++) {
        const mark = visited.has(i) ? ' ✓' : '  ';
        const name = i === scenarios.length - 1
          ? `→ ${scenarios[i].name}`
          : scenarios[i].name;
        console.log(`    [${i + 1}]${mark} ${name}`);
      }
      console.log();

      const choice = await getChoice(scenarios.length);
      const idx = choice - 1;

      console.log(`\n  ── [${choice}] ${scenarios[idx].name} ──\n`);
      await scenarios[idx].fn();
      visited.add(idx);

      if (idx === scenarios.length - 1) break;

      await pause();
    }
  }

  function close() {
    rl.close();
  }

  return { pause, explore, close };
}
