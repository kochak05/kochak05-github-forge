// The entry <-> env lifecycle: bind an ephemeral port, register it with the env, then poll
// until the env says the trial is over and exit 0.
//
//   1. MAKEFUN_ENV_URL names the env's origin (http://store:8080 in a trial container).
//      Without it there is nothing to talk to, so the program exits 1 at once.
//   2. The server listens on port 0 and the kernel picks a free one. Never bind 8080:
//      that is the env's port, and on the one-pod layout it shares the loopback.
//   3. POST $MAKEFUN_ENV_URL/register {"port": N}. The env records the address the
//      request came from plus N as the base URL and dials it from then on. The first
//      register wins: a 409 means another entry already registered, and this process
//      keeps waiting like any other.
//   4. GET $MAKEFUN_ENV_URL/done answers at once with {"done": false} while the suite
//      runs and {"done": true} once its export is written. Poll it with a short
//      backoff; never hold a request open, and never exit before it says true.
//   5. Close the server and exit 0. The harness stops the env afterwards, and the
//      env's export is what the scorer reads.
//
// main.ts imports its own server and nothing else: no package, no Node built-in, no
// model call. The suite scores the server app.ts builds; the lifecycle is the
// harness's, not the contest's.

import { createApp } from './app.ts';

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (ENV_URL === '') {
  process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
  process.exit(1);
}

/** One request may take this long before it is abandoned and retried. */
const REQUEST_TIMEOUT_MS = 30_000;
/** The waits between retries: exponential from the first, capped at the longest. */
const RETRY_FIRST_MS = 250;
const RETRY_LAST_MS = 2_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** The wait after `failures` failed attempts: exponential, capped. */
function backoffMs(failures: number): number {
  return Math.min(RETRY_LAST_MS, RETRY_FIRST_MS * 2 ** Math.min(failures, 8));
}

/**
 * POST the bound port until the env accepts it. 200 is the normal answer and 409 means
 * a first register already won, which is not this process's to fix; both end the loop.
 * 400 and 405 are contract errors and end the program. Anything else is retried,
 * since the env may still be starting.
 */
async function register(port: number): Promise<void> {
  let failures = 0;
  for (;;) {
    let status: number | null = null;
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      status = res.status;
      if (status === 200 || status === 409) return;
      if (status === 400 || status === 405) {
        throw new Error(`register answered HTTP ${status}: ${await res.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    failures += 1;
    await sleep(backoffMs(failures));
  }
}

/** Poll GET /done until it answers {"done": true}; never return before that. */
async function waitUntilDone(): Promise<void> {
  let failures = 0;
  for (;;) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
      failures = 0;
    } catch {
      // The env is not answering yet, or the poll timed out: it is not done, so poll again.
      failures += 1;
    }
    await sleep(backoffMs(failures));
  }
}

/** Bind the port, register it, then wait for the env: the whole life of the process. */
async function run(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the server did not bind an ephemeral TCP port');
  }
  process.stdout.write(`[entry] listening on port ${address.port}; env ${ENV_URL}\n`);

  // A trial pod stops the process with a signal, not with /done. Close the
  // listener instead of dying mid-request, and leave within a few seconds even
  // if an idle keep-alive connection lingers: the harness reads the env's
  // export, not this process's exit code.
  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);

  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');

  await waitUntilDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
