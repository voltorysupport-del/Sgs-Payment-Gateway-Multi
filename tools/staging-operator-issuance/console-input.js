/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS package. */
/* global module, process */
// Raw console input disables OS echo. Never print characters, lengths or exceptions.
function readHiddenLine(prompt, input = process.stdin, output = process.stdout, signal) {
  return new Promise((resolve, reject) => {
    if (
      signal?.aborted ||
      !input.isTTY ||
      !output.isTTY ||
      typeof input.setRawMode !== 'function'
    ) {
      reject(new Error('Interactive console required.'));
      return;
    }
    const wasRaw = input.isRaw === true;
    const characters = [];
    let settled = false;
    function finish(failed) {
      if (settled) return;
      settled = true;
      input.removeListener('data', data);
      input.removeListener('error', failure);
      input.removeListener('end', failure);
      input.removeListener('close', failure);
      process.removeListener('SIGTERM', failure);
      signal?.removeEventListener('abort', failure);
      let restored = true;
      try {
        input.setRawMode(wasRaw);
      } catch {
        restored = false;
      }
      input.pause();
      const text = failed || !restored ? undefined : characters.join('');
      characters.fill('');
      output.write('\n');
      if (failed || !restored) reject(new Error('Console input cancelled.'));
      else resolve(text);
    }
    function failure() {
      finish(true);
    }
    function data(chunk) {
      for (const character of chunk) {
        if (character === '\r' || character === '\n') {
          finish(false);
          return;
        }
        if (character === '\b' || character === '\x7f') {
          characters.pop();
          continue;
        }
        // Includes Ctrl+C, Ctrl+D, Ctrl+Z, escape sequences and unsupported paste controls.
        if (character < ' ' || character === '\u009b' || characters.length >= 32768) {
          finish(true);
          return;
        }
        characters.push(character);
      }
    }
    try {
      input.setEncoding('utf8');
      input.setRawMode(true);
      input.on('data', data);
      input.once('error', failure);
      input.once('end', failure);
      input.once('close', failure);
      process.once('SIGTERM', failure);
      signal?.addEventListener('abort', failure, { once: true });
      output.write(prompt);
      input.resume();
    } catch {
      finish(true);
    }
  });
}
module.exports = { readHiddenLine };
