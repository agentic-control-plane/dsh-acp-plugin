// The bundle patch names the package dsh imports at boot. When it named the
// package's old npm name, every profile that listed this bundle failed to
// start ("Cannot find package 'dsh-plugin-acp'").
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('cordis.patch.yml mounts the plugin under this package\'s own name', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  const patch = readFileSync(new URL('../cordis.patch.yml', import.meta.url), 'utf8')
  const names = [...patch.matchAll(/^\s*name:\s*['"]?([^'"\n]+)['"]?\s*$/gm)].map(m => m[1])
  assert.deepEqual(names, [pkg.name])
})
