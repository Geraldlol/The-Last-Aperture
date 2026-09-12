import { spawn } from 'node:child_process'
import { constants as fsConstants } from 'node:fs'
import {
  link,
  open,
  rename,
  unlink,
} from 'node:fs/promises'
import {
  dirname,
  isAbsolute,
  join,
  resolve,
} from 'node:path'
import { fileURLToPath } from 'node:url'

const WIN32_MOVE_WORKER = fileURLToPath(
  new URL('./win32-durable-move-worker.ps1', import.meta.url),
)

let win32Worker = null
let nextRequestId = 1

function publicationError(code, message, options = {}) {
  const error = new Error(message, options.cause ? { cause: options.cause } : undefined)
  error.name = 'DurableFilePublicationError'
  error.code = code
  if (options.win32Error !== undefined) error.win32_error = options.win32Error
  return error
}

function mappedWin32Code(value) {
  if ([2, 3].includes(value)) return 'ENOENT'
  if ([80, 183].includes(value)) return 'EEXIST'
  if (value === 5) return 'EACCES'
  if (value === 17) return 'EXDEV'
  if ([32, 33].includes(value)) return 'EBUSY'
  if (value === 87) return 'EINVAL'
  return 'WIN32_DURABLE_MOVE_FAILED'
}

function referenceWorker(worker) {
  worker.child.ref()
  worker.child.stdin.ref?.()
  worker.child.stdout.ref?.()
  worker.child.stderr.ref?.()
}

function unreferenceWorker(worker) {
  worker.child.unref()
  worker.child.stdin.unref?.()
  worker.child.stdout.unref?.()
  worker.child.stderr.unref?.()
}

function rejectWorker(worker, cause) {
  if (win32Worker === worker) win32Worker = null
  const error = publicationError(
    'WIN32_DURABLE_MOVE_WORKER_FAILED',
    `Win32 durable-move worker failed${worker.stderr === '' ? '' : `: ${worker.stderr}`}`,
    { cause },
  )
  for (const pending of worker.pending.values()) pending.reject(error)
  worker.pending.clear()
}

function startWin32Worker() {
  const systemRoot = process.env.SystemRoot
  if (typeof systemRoot !== 'string' || !isAbsolute(systemRoot)) {
    throw publicationError(
      'WIN32_DURABLE_MOVE_WORKER_FAILED',
      'SystemRoot is unavailable for the controller-owned Win32 durability helper',
    )
  }
  const powerShell = join(resolve(systemRoot), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  const child = spawn(powerShell, [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    WIN32_MOVE_WORKER,
  ], {
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  })
  child.stdin.setDefaultEncoding('utf8')
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  const worker = {
    child,
    pending: new Map(),
    stdout: '',
    stderr: '',
    failed: false,
  }
  child.stdout.on('data', (chunk) => {
    worker.stdout += chunk
    while (true) {
      const newline = worker.stdout.indexOf('\n')
      if (newline < 0) break
      const line = worker.stdout.slice(0, newline).trim()
      worker.stdout = worker.stdout.slice(newline + 1)
      if (line === '') continue
      let response
      try {
        response = JSON.parse(line)
      } catch (cause) {
        worker.failed = true
        rejectWorker(worker, cause)
        child.kill()
        return
      }
      const pending = worker.pending.get(response.id)
      if (pending === undefined) continue
      worker.pending.delete(response.id)
      if (response.ok === true) {
        pending.resolve()
      } else {
        const code = mappedWin32Code(response.win32_error)
        pending.reject(publicationError(
          code,
          `Win32 write-through move failed: ${response.message ?? 'unknown error'}`,
          { win32Error: response.win32_error },
        ))
      }
      if (worker.pending.size === 0) unreferenceWorker(worker)
    }
  })
  child.stderr.on('data', (chunk) => {
    worker.stderr = `${worker.stderr}${chunk}`.slice(-8192)
  })
  child.once('error', (cause) => {
    worker.failed = true
    rejectWorker(worker, cause)
  })
  child.once('exit', (code, signal) => {
    if (worker.failed || worker.pending.size === 0) {
      if (win32Worker === worker) win32Worker = null
      return
    }
    worker.failed = true
    rejectWorker(worker, new Error(`worker exited (${code ?? signal ?? 'unknown'})`))
  })
  unreferenceWorker(worker)
  return worker
}

async function moveFileWithWin32WriteThrough(source, destination, replace) {
  const worker = win32Worker ?? startWin32Worker()
  win32Worker = worker
  const id = nextRequestId
  nextRequestId += 1
  referenceWorker(worker)
  return new Promise((resolvePromise, rejectPromise) => {
    worker.pending.set(id, { resolve: resolvePromise, reject: rejectPromise })
    const payload = `${JSON.stringify({
      id,
      source: resolve(source),
      destination: resolve(destination),
      replace,
    })}\n`
    worker.child.stdin.write(payload, 'utf8', (error) => {
      if (error === null || error === undefined) return
      const pending = worker.pending.get(id)
      if (pending === undefined) return
      worker.pending.delete(id)
      pending.reject(publicationError(
        'WIN32_DURABLE_MOVE_WORKER_FAILED',
        'could not submit Win32 write-through move',
        { cause: error },
      ))
      if (worker.pending.size === 0) unreferenceWorker(worker)
    })
  })
}

export async function syncDirectoryDurably(path) {
  if (process.platform === 'win32') {
    throw publicationError(
      'DIRECTORY_FSYNC_UNSUPPORTED',
      'Node cannot open a Win32 directory with the handle semantics required for durable fsync',
    )
  }
  const handle = await open(path, fsConstants.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

export async function replaceFileDurably(source, destination, options = {}) {
  const platform = options.platform ?? process.platform
  if (platform === 'win32') {
    const moveImpl = options.win32MoveImpl ?? moveFileWithWin32WriteThrough
    await moveImpl(source, destination, true)
    return
  }
  await rename(source, destination)
  await (options.directorySyncImpl ?? syncDirectoryDurably)(dirname(resolve(destination)))
}

export async function publishFileCreateOnlyDurably(source, destination, options = {}) {
  const platform = options.platform ?? process.platform
  if (platform === 'win32') {
    const moveImpl = options.win32MoveImpl ?? moveFileWithWin32WriteThrough
    await moveImpl(source, destination, false)
    await options.afterVisible?.()
    return
  }
  await link(source, destination)
  await options.afterVisible?.()
  const syncImpl = options.directorySyncImpl ?? syncDirectoryDurably
  await syncImpl(dirname(resolve(destination)))
  await unlink(source)
  await syncImpl(dirname(resolve(destination)))
}

// Lock directories and already-published temporary cleanup are recoverable
// coordination state. POSIX persists their namespace changes; Win32 does not
// pretend an unsupported directory fsync succeeded. Evidence publication uses
// the write-through primitives above before this cleanup boundary is reached.
export async function syncRecoverableDirectoryChange(path) {
  if (process.platform === 'win32') return
  await syncDirectoryDurably(path)
}
