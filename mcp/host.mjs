// The MCP server's `Host` (hooks/outgoing.ts) over Node: how the shared check runs a program and reads a
// file outside the engine. It keeps the engine's rules, so both give the same answer: no shell, each
// output stream kept up to 4 MiB as a clean start, a timeout rejects, a file over 4 MiB isn't read.
import { spawn } from 'node:child_process'
import { access, readFile, stat } from 'node:fs/promises'

/** As the engine: each output stream, and a file read, up to 4 MiB. Same as MAX_BYTES in outgoing.ts. */
export const MAX_BYTES = 4 * 1024 * 1024
const KILL_GRACE_MS = 2000

/**
 * Runs a program like the engine's `$.process.run`: argv as given with no shell, each stream kept up to
 * MAX_BYTES (cut to exactly its first MAX_BYTES, never with a hole), and a run past `timeoutMs` (30 s by
 * default) rejects with "timed out" at once, its process killed. A program killed by a signal exits 1.
 */
export function run(argv, init = {}) {
  return new Promise((done, fail) => {
    const ms = init.timeoutMs ?? 30_000
    let settled = false
    let timer
    const settle = (fn, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      fn(value)
    }
    let child
    try {
      // argv is ['git', ...] or a scanner program the check found itself, and there is no shell, so no
      // word in it can become a command.
      // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
      child = spawn(argv[0], argv.slice(1), {
        cwd: init.cwd,
        env: { ...process.env, ...(init.env ?? {}) },
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch (err) {
      settle(fail, err)
      return
    }
    const streams = { stdout: { parts: [], size: 0, cut: false }, stderr: { parts: [], size: 0, cut: false } }
    const take = which => chunk => {
      const s = streams[which]
      if (s.cut) return
      const room = MAX_BYTES - s.size
      if (chunk.length > room) {
        s.parts.push(chunk.subarray(0, room))
        s.size = MAX_BYTES
        s.cut = true
        return
      }
      s.parts.push(chunk)
      s.size += chunk.length
    }
    child.stdout.on('data', take('stdout'))
    child.stderr.on('data', take('stderr'))
    timer = setTimeout(() => {
      child.kill()
      setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS).unref()
      // Answer now: a grandchild holding the pipes open must not hold the check.
      settle(fail, new Error(`${argv[0]} timed out after ${ms} ms`))
    }, ms)
    child.on('error', err => settle(fail, err))
    child.on('close', code => settle(done, {
      exitCode: code ?? 1,
      stdout: Buffer.concat(streams.stdout.parts).toString('utf8'),
      stderr: Buffer.concat(streams.stderr.parts).toString('utf8'),
      isStdoutTruncated: streams.stdout.cut,
      isStderrTruncated: streams.stderr.cut,
    }))
    child.stdin.on('error', () => { /* a program that exits before reading all of stdin */ })
    child.stdin.end(init.stdin ?? '')
  })
}

/**
 * Reads a whole file as text; throws for one over MAX_BYTES, as the engine does. The size is checked on
 * what was read, so a file that grows meanwhile can't slip past. A binary file is read as text too: a key
 * stored in it is still found, where refusing it would only check its name.
 */
export async function read(path) {
  if ((await stat(path)).size > MAX_BYTES) throw new Error('over 4 MiB')
  const bytes = await readFile(path)
  if (bytes.length > MAX_BYTES) throw new Error('over 4 MiB')
  return bytes.toString('utf8')
}

/** Whether a path exists: false when it is missing, and an error for anything else (no permission). */
export function exists(path) {
  return access(path).then(() => true, err => {
    if (err.code === 'ENOENT' || err.code === 'ENOTDIR') return false
    throw err
  })
}
