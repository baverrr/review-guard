// Builds the MCP server's copy of the guard's check: hooks/{scan,scanners,outgoing,status}.ts with their
// types stripped, as mcp/lib/*.mjs. The server runs on Node 22 or newer, and some Node builds can't run
// TypeScript, so it uses this copy. Each file's first line records two fingerprints: of the .ts it came
// from, and of the built text below it. The server refuses a copy where either doesn't match.
//
// Run it with Node 22.13 or newer (which can strip types) after changing those files:
//   node scripts/build-mcp.mjs           write mcp/lib/
//   node scripts/build-mcp.mjs --check   exit 1 if mcp/lib/ doesn't match hooks/ (as the server checks
//                                        it, so the same on every Node version), or doesn't load
//
// server.mjs repeats SOURCES and the fingerprint rule (it can't import this file, which runs the
// build): change both together.
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import * as nodeModule from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const SOURCES = ['scan', 'scanners', 'outgoing', 'status']
const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const lib = name => join(root, 'mcp', 'lib', `${name}.mjs`)

/** sha256 of a text with its line endings made LF, so a checkout with Windows line endings matches. */
const fingerprint = text => createHash('sha256').update(text.replace(/\r\n/g, '\n')).digest('hex')
const HEADER = /^\/\/ Generated .* source-sha256: (\w+) built-sha256: (\w+)\r?\n/

function build(name) {
  if (typeof nodeModule.stripTypeScriptTypes !== 'function') {
    throw new Error(`this Node (${process.version}) can't strip TypeScript types: use Node 22.13 or newer`)
  }
  const source = readFileSync(join(root, 'hooks', `${name}.ts`), 'utf8')
  // `strip` mode only blanks types, so a line in the .mjs is the same line of the .ts plus one (the header).
  const js = nodeModule.stripTypeScriptTypes(source, { mode: 'strip' })
    .replace(/(from\s+['"]\.\/[\w-]+)\.ts(['"])/g, '$1.mjs$2')
  // Every relative import must now name a built .mjs: anything else would only fail when the server runs.
  const loose = [...js.matchAll(/(?:from|import)\s*\(?\s*['"](\.{1,2}\/[^'"]*)['"]/g)].map(m => m[1]).filter(p => !/^\.\/[\w-]+\.mjs$/.test(p))
  if (loose.length > 0) throw new Error(`hooks/${name}.ts imports ${loose.join(', ')}: write runtime imports as './name.ts' of a file in SOURCES`)
  return `// Generated from hooks/${name}.ts by scripts/build-mcp.mjs. Do not edit. source-sha256: ${fingerprint(source)} built-sha256: ${fingerprint(js)}\n${js}`
}

/** Why mcp/lib/<name>.mjs doesn't match, or undefined: the same test the server makes. */
function mismatch(name) {
  let source, built
  try {
    source = readFileSync(join(root, 'hooks', `${name}.ts`), 'utf8')
    built = readFileSync(lib(name), 'utf8')
  } catch (err) {
    return `can't be read (${err.code ?? err.message})`
  }
  const header = HEADER.exec(built)
  if (!header || header[1] !== fingerprint(source)) return `does not match hooks/${name}.ts`
  if (header[2] !== fingerprint(built.slice(header[0].length))) return 'was changed after it was built'
  return undefined
}

const check = process.argv.includes('--check')
let bad = 0
for (const name of SOURCES) {
  if (check) {
    const why = mismatch(name)
    if (why) {
      console.error(`mcp/lib/${name}.mjs ${why} (run node scripts/build-mcp.mjs)`)
      bad++
    }
  } else {
    mkdirSync(dirname(lib(name)), { recursive: true })
    writeFileSync(lib(name), build(name))
    console.log(`wrote mcp/lib/${name}.mjs`)
  }
}
// The built files must also load: a broken import shows here, not first when the server runs.
if (bad === 0) {
  for (const name of SOURCES) {
    try {
      await import(pathToFileURL(lib(name)).href)
    } catch (err) {
      console.error(`mcp/lib/${name}.mjs does not load: ${err.message}`)
      bad++
    }
  }
}
if (bad > 0) process.exit(1)
