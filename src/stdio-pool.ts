/**
 * Pool of long-running `gbrain serve` child processes (stdio MCP).
 *
 * Each child runs the JSON-RPC MCP protocol over its stdin/stdout. We keep N
 * children pre-warm so we don't pay the spawn cost on every HTTP request.
 *
 * The pool serializes requests per child: at any moment, a child is either
 * idle or processing exactly one request/response pair. Pool.acquire() waits
 * until a child is free, hands it out, and Pool.release() returns it.
 *
 * Children are restarted automatically if they exit unexpectedly.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';

// gbrain CLI is a TypeScript file with #!/usr/bin/env bun shebang. Under systemd
// the spawned child gets a stripped-down PATH and the shebang lookup fails (exit
// 127). Spawn through bun explicitly so we don't depend on PATH inheritance.
const BUN_BIN = process.env.BUN_BIN || `${process.env.HOME}/.bun/bin/bun`;
const GBRAIN_BIN = process.env.GBRAIN_BIN || `${process.env.HOME}/.bun/bin/gbrain`;
const POOL_SIZE = Number(process.env.GBRAIN_POOL_SIZE || 3);
const REQUEST_TIMEOUT_MS = 60_000;

interface Worker {
  id: number;
  proc: ChildProcessWithoutNullStreams;
  busy: boolean;
  buffer: string;
  pendingResolve?: (response: any) => void;
  pendingReject?: (err: Error) => void;
  pendingId?: number | string;
}

const workers: Worker[] = [];
const waiters: Array<(w: Worker) => void> = [];

function spawnWorker(id: number): Worker {
  // Spawn through bun explicitly: gbrain is a .ts file with bun shebang, but
  // PATH-based shebang resolution can fail under systemd's stripped env.
  const proc = spawn(BUN_BIN, ['run', GBRAIN_BIN, 'serve'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PATH: `${process.env.HOME}/.bun/bin:${process.env.PATH || '/usr/bin:/bin'}` },
  });
  const worker: Worker = { id, proc, busy: false, buffer: '' };

  proc.stdout.on('data', (chunk: Buffer) => {
    worker.buffer += chunk.toString('utf8');
    // Each MCP message is one JSON object terminated by newline
    let nl: number;
    while ((nl = worker.buffer.indexOf('\n')) !== -1) {
      const line = worker.buffer.slice(0, nl).trim();
      worker.buffer = worker.buffer.slice(nl + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (worker.pendingResolve && (msg.id === worker.pendingId || msg.id === undefined)) {
          worker.pendingResolve(msg);
          worker.pendingResolve = undefined;
          worker.pendingReject = undefined;
          worker.pendingId = undefined;
        }
      } catch (e) {
        console.error(`[pool worker=${id}] parse error:`, line.slice(0, 200));
      }
    }
  });

  proc.stderr.on('data', (chunk: Buffer) => {
    // gbrain serve prints info to stderr (PgBouncer note, etc.) — log but don't fail
    const msg = chunk.toString('utf8').trim();
    if (msg && process.env.LOG_GBRAIN_STDERR === '1') {
      console.error(`[pool worker=${id}] gbrain:`, msg.slice(0, 200));
    }
  });

  proc.on('exit', (code) => {
    console.error(`[pool worker=${id}] exited with code ${code}, respawning...`);
    if (worker.pendingReject) {
      worker.pendingReject(new Error(`worker exited mid-request (code ${code})`));
    }
    // Respawn after small delay to avoid tight loop on persistent error
    setTimeout(() => {
      const idx = workers.indexOf(worker);
      if (idx !== -1) workers[idx] = spawnWorker(id);
    }, 1000);
  });

  return worker;
}

export function initPool(): void {
  for (let i = 0; i < POOL_SIZE; i++) {
    workers.push(spawnWorker(i));
  }
  console.error(`[pool] spawned ${POOL_SIZE} gbrain serve workers`);
}

function findIdle(): Worker | undefined {
  return workers.find(w => !w.busy && !w.proc.killed);
}

async function acquire(): Promise<Worker> {
  const idle = findIdle();
  if (idle) {
    idle.busy = true;
    return idle;
  }
  return new Promise<Worker>((resolve) => {
    waiters.push((w) => {
      w.busy = true;
      resolve(w);
    });
  });
}

function release(worker: Worker): void {
  worker.busy = false;
  worker.buffer = '';
  const next = waiters.shift();
  if (next) next(worker);
}

/**
 * Send a JSON-RPC request through the pool and wait for the response.
 * The caller passes the full JSON-RPC envelope; we add nothing.
 *
 * If the message is a JSON-RPC notification (no `id`), we write it to stdin
 * and return immediately — there will be no response per spec.
 */
export async function callMcp(rpc: any): Promise<any> {
  const worker = await acquire();
  try {
    const id = rpc.id;
    if (id === undefined) {
      // Notification — no response expected
      worker.proc.stdin.write(JSON.stringify(rpc) + '\n');
      return { ok: true, notification: true };
    }
    return await new Promise<any>((resolve, reject) => {
      const timer = setTimeout(() => {
        worker.pendingResolve = undefined;
        worker.pendingReject = undefined;
        reject(new Error('request timeout'));
      }, REQUEST_TIMEOUT_MS);

      worker.pendingResolve = (res) => { clearTimeout(timer); resolve(res); };
      worker.pendingReject = (err) => { clearTimeout(timer); reject(err); };
      worker.pendingId = id;

      worker.proc.stdin.write(JSON.stringify(rpc) + '\n');
    });
  } finally {
    release(worker);
  }
}

export function poolStatus() {
  return {
    size: workers.length,
    busy: workers.filter(w => w.busy).length,
    waiters: waiters.length,
  };
}

export function shutdownPool(): void {
  for (const w of workers) {
    try { w.proc.kill('SIGTERM'); } catch {}
  }
}
