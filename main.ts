// Entry point: boots the forge server, registers it with the grading
// environment ("env"), then waits until the env says the trial is done.
//
// The env lives at MAKEFUN_ENV_URL. The forge itself binds an ephemeral
// port (never 8080 — that port belongs to the env), tells the env that
// port, and then polls the env until it reports done. Everything the env
// is slow to answer gets retried forever with exponential backoff, because
// the env may still be starting up when we first reach it.
import { createApp } from './app.ts';

// How long any single request to the env may take before we give up on it.
const REQUEST_TIMEOUT_MS = 30_000;

// Retry pacing: start short, double after each miss, never wait longer
// than this between attempts.
const FIRST_RETRY_MS = 250;
const MAX_RETRY_MS = 2_000;

/** A promise that resolves after `ms` milliseconds. */
function nap(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * One retry schedule. Each call to `pause()` waits the current delay and
 * then doubles it (up to the cap), so the first pause is short and later
 * pauses back off. A fresh schedule starts at the short delay again.
 */
class RetrySchedule {
  private delay = FIRST_RETRY_MS;

  async pause(): Promise<void> {
    const waitFor = this.delay;
    this.delay = Math.min(this.delay * 2, MAX_RETRY_MS);
    await nap(waitFor);
  }
}

/** The env origin with any trailing slashes removed, or null when unset. */
function envOrigin(): string | null {
  const raw = process.env.MAKEFUN_ENV_URL;
  if (raw === undefined || raw === '') {
    return null;
  }
  // Strip trailing slashes so joining paths never yields a double slash.
  let end = raw.length;
  while (end > 0 && raw[end - 1] === '/') {
    end -= 1;
  }
  const trimmed = raw.slice(0, end);
  return trimmed === '' ? null : trimmed;
}

/**
 * Tell the env which port the forge bound. Returns once the env accepts
 * the registration (200) or tells us it already has one (409). A 400 or
 * 405 means our request disagrees with the env's contract, which no
 * amount of retrying will fix, so it is fatal. Anything else — the env
 * being unreachable, a timeout, any other status — is retried forever.
 */
async function registerWithEnv(origin: string, port: number): Promise<void> {
  const schedule = new RetrySchedule();
  for (;;) {
    let response: Response | null = null;
    try {
      response = await fetch(`${origin}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      // The env is unreachable or the request timed out: wait and retry.
      await schedule.pause();
      continue;
    }
    if (response.status === 200 || response.status === 409) {
      return;
    }
    if (response.status === 400 || response.status === 405) {
      throw new Error(`env rejected registration with status ${response.status}`);
    }
    await schedule.pause();
  }
}

/**
 * Poll the env until it reports the trial is finished. Any answer other
 * than a 200 whose JSON body has done === true — a non-OK status, a body
 * that is not JSON, done still false, a network failure, a timeout —
 * just means "not yet", so we wait and ask again, forever.
 */
async function waitForEnvDone(origin: string): Promise<void> {
  const schedule = new RetrySchedule();
  for (;;) {
    let finished = false;
    try {
      const response = await fetch(`${origin}/done`, {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.ok) {
        const body: unknown = await response.json();
        finished =
          typeof body === 'object' &&
          body !== null &&
          (body as { done?: unknown }).done === true;
      }
    } catch {
      // Not JSON, unreachable, or timed out: still not done.
      finished = false;
    }
    if (finished) {
      return;
    }
    await schedule.pause();
  }
}

/** Bind the forge to an ephemeral port and return the port the kernel chose. */
async function bindEphemeral(server: ReturnType<typeof createApp>): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const bound = server.address();
  if (typeof bound !== 'object' || bound === null) {
    throw new Error('server did not bind a TCP port');
  }
  return bound.port;
}

/** Close the server, resolving once it has fully shut down. */
async function shutDown(server: ReturnType<typeof createApp>): Promise<void> {
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
}

/**
 * The whole lifecycle: boot the forge, register it, wait for the env to
 * finish, then shut down.
 */
async function run(): Promise<void> {
  const origin = envOrigin();
  if (origin === null) {
    process.stderr.write(
      '[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n',
    );
    process.exit(1);
  }

  const server = createApp();
  const port = await bindEphemeral(server);
  process.stdout.write(`[entry] listening on port ${port}\n`);

  await registerWithEnv(origin, port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');

  await waitForEnvDone(origin);

  await shutDown(server);
  process.stdout.write('[entry] done\n');
}

run()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`[entry] ${message}\n`);
    process.exit(1);
  });
