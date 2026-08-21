const { readFileSync, writeFileSync } = require('fs')
const { join } = require('path')

const root = join(__dirname, '..')
const loaderPath = join(root, 'index.js')
const typesPath = join(root, 'index.d.ts')

// The legacy per-browser Node exports (cachy/operaGx/octoBrowser/internetExplorer/safari)
// are each gated to the OS(es) that browser is registered on. Rather than hand-typing that
// gate in three separate places (the loader's platformNative() calls, the generated .d.ts
// facade, and the list of names to exclude from the "napi declared it" completeness check),
// derive it once from the platform contract those OS gates actually come from.
const registryPath = join(root, '..', '..', 'rookie-rs', 'browser_registry.json')
const registry = JSON.parse(readFileSync(registryPath, 'utf8'))

const REGISTRY_PLATFORM_TO_NODE_PLATFORM = { windows: 'win32', macos: 'darwin', linux: 'linux' }
const NODE_PLATFORM_DISPLAY_NAME = { win32: 'Windows', darwin: 'macOS', linux: 'Linux' }

// napi-rs Node function name -> canonical browser ID in browser_registry.json. The names
// differ (camelCase Node export vs snake_case registry ID), so this glue table is the only
// hand-maintained part; the platforms each maps to are looked up, not typed in.
const LEGACY_PLATFORM_FUNCTIONS = {
  cachy: 'cachy',
  operaGx: 'opera_gx',
  octoBrowser: 'octo_browser',
  internetExplorer: 'internet_explorer',
  safari: 'safari',
}

function nodePlatformsForCanonicalId(canonicalId) {
  const platforms = []
  for (const [registryPlatform, browsers] of Object.entries(registry.platforms)) {
    if (browsers.some((browser) => browser.canonical_id === canonicalId)) {
      const nodePlatform = REGISTRY_PLATFORM_TO_NODE_PLATFORM[registryPlatform]
      if (!nodePlatform) {
        throw new Error(`patch-loader.js: unrecognized registry platform '${registryPlatform}'`)
      }
      platforms.push(nodePlatform)
    }
  }
  if (platforms.length === 0) {
    throw new Error(
      `patch-loader.js: '${canonicalId}' is not registered on any platform in browser_registry.json`
    )
  }
  return platforms.sort()
}

const legacyFunctionPlatforms = Object.fromEntries(
  Object.entries(LEGACY_PLATFORM_FUNCTIONS).map(([functionName, canonicalId]) => [
    functionName,
    nodePlatformsForCanonicalId(canonicalId),
  ])
)

function nodePlatformDisplayList(nodePlatforms) {
  const names = nodePlatforms.map((platform) => NODE_PLATFORM_DISPLAY_NAME[platform])
  return names.length === 1
    ? names[0]
    : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

function platformNativeExportLine(functionName) {
  const nodePlatforms = legacyFunctionPlatforms[functionName]
  const platformArg =
    nodePlatforms.length === 1
      ? `'${nodePlatforms[0]}'`
      : `[${nodePlatforms.map((platform) => `'${platform}'`).join(', ')}]`
  const supportedPlatform = nodePlatformDisplayList(nodePlatforms)
  return `module.exports.${functionName} = platformNative(${functionName}, '${functionName}', ${platformArg}, '${supportedPlatform}')`
}

function legacyPlatformDeclarations() {
  const groups = []
  const groupByPlatformKey = new Map()
  for (const functionName of Object.keys(LEGACY_PLATFORM_FUNCTIONS)) {
    const platforms = legacyFunctionPlatforms[functionName]
    const platformKey = platforms.join(',')
    let group = groupByPlatformKey.get(platformKey)
    if (!group) {
      group = { platforms, functionNames: [] }
      groupByPlatformKey.set(platformKey, group)
      groups.push(group)
    }
    group.functionNames.push(functionName)
  }
  return groups
    .map(({ platforms, functionNames }) => {
      const heading = `/** ${nodePlatformDisplayList(platforms)}-only browsers */`
      const declarations = functionNames.map(
        (functionName) =>
          `export declare function ${functionName}(domains?: Array<string> | undefined | null, timeoutMs?: number | undefined | null, cancellation?: CancellationHandle | undefined | null): Promise<Array<CookieObject>>`
      )
      return [heading, ...declarations].join('\n')
    })
    .join('\n')
}

let loader = readFileSync(loaderPath, 'utf8')

if (!loader.includes('const { platform, arch } = process')) {
  loader = loader.replace(
    "const { readFileSync } = require('fs')\n",
    "const { readFileSync } = require('fs')\nconst { platform, arch } = process\n"
  )
}

if (
  loader.includes('let loadError = null') &&
  !loader.includes("const { optionalDependencies = {} } = require('./package.json')")
) {
  loader = loader.replace(
    'const { platform, arch } = process\n',
    "const { platform, arch } = process\nconst { optionalDependencies = {} } = require('./package.json')\n"
  )
}

if (!loader.includes('No prebuilt rookie-cookies binding is published')) {
  loader = loader.replace(
    'if (!nativeBinding) {\n  if (loadError) {',
    `if (!nativeBinding) {
  if (loadError && loadError.code === 'MODULE_NOT_FOUND') {
    const missingPackage = loadError.message.match(
      /['"](rookie-cookies-[^'"]+)['"]/
    )
    if (
      missingPackage &&
      !Object.prototype.hasOwnProperty.call(optionalDependencies, missingPackage[1])
    ) {
      throw new Error(
        \`No prebuilt rookie-cookies binding is published for \${platform}-\${arch}; build the Node binding from source or use a supported platform\`
      )
    }
  }
  if (loadError) {`
  )
}

const canonicalNativeBindingDestructure =
  'const { CancellationHandle, version, toNetscape, anyBrowser, extractFromPath, cookiesFromPath, chromiumCookiesFromPath, chromiumCookiesFromPathDetailed, firefox, firefoxProfiles, firefoxProfile, zen, librewolf, cachy, chrome, chromeProfiles, chromeProfile, brave, arc, edge, opera, operaGx, chromium, vivaldi, firefoxBased, firefoxBasedDetailed, supportedBrowsers, browserProfiles, browserReport, loadReport, load, octoBrowser, internetExplorer, safari, chromiumBased, chromiumBasedDetailed, read, jar, ReadResult, profiles, report, fromPath, testWorkerPanic } = nativeBinding'
const nativeBindingDestructurePattern = /^const \{ .*\bversion\b.*\} = nativeBinding$/m
const napiV3ExportFacadePattern =
  /^module\.exports = nativeBinding\n(?:module\.exports\.(\w+) = nativeBinding\.\1\n?)+/m

let exportStart
if (nativeBindingDestructurePattern.test(loader)) {
  loader = loader.replace(nativeBindingDestructurePattern, canonicalNativeBindingDestructure)

  // napi-rs v2 follows the destructure with self-reexports. An already
  // patched loader instead follows it with this script's validation helpers.
  exportStart = loader.search(
    /^(?:function (?:requiredNative|asyncNative|unsupportedPlatform|platformNative)\(|module\.exports\.(\w+) = \1$)/m
  )
} else {
  // napi-rs v3 stopped destructuring the binding and emits a
  // `module.exports = nativeBinding` facade instead. Cut that whole facade
  // and install the same explicit local bindings the validation layer uses.
  const napiV3ExportFacade = loader.match(napiV3ExportFacadePattern)
  if (napiV3ExportFacade) {
    loader =
      loader.slice(0, napiV3ExportFacade.index) + canonicalNativeBindingDestructure + '\n\n'
    exportStart = loader.length
  }
}

if (exportStart === undefined || exportStart === -1) {
  throw new Error(
    'patch-loader.js: could not find the napi-generated native binding export facade; napi-rs output format may have changed'
  )
}

loader = loader.slice(0, exportStart)
loader += `function requiredNative(nativeFunction, name) {
  if (typeof nativeFunction !== 'function') {
    throw new TypeError(\`Expected a native binding function: \${name}\`)
  }
  return nativeFunction
}

const structuredErrorPrefix = '__ROOKIE_ERROR_V1__'
const requestStatusCodes = new Set([
  'InvalidArg',
  'ObjectExpected',
  'StringExpected',
  'NameExpected',
  'FunctionExpected',
  'NumberExpected',
  'BooleanExpected',
  'ArrayExpected',
  'BigintExpected',
  'DateExpected',
  'ArrayBufferExpected',
  'DetachableArraybufferExpected',
])

function decorateNativeError(error) {
  if (!error || (typeof error !== 'object' && typeof error !== 'function')) {
    return error
  }

  let details
  if (
    typeof error.message === 'string'
    && error.message.startsWith(structuredErrorPrefix)
  ) {
    try {
      details = JSON.parse(error.message.slice(structuredErrorPrefix.length))
      // Only overwrite with a real string. A payload without a message would
      // otherwise be coerced by the Error setter to the literal "undefined",
      // destroying the native text -- and the catch below cannot recover it,
      // because the parse succeeded.
      if (typeof details?.message === 'string') {
        error.message = details.message
      }
    } catch (_) {
      // Preserve the native message if a future payload is not understood by
      // this loader version, then attach safe diagnostic defaults below.
    }
  }

  error.kind = details?.kind
    ?? (error instanceof TypeError || requestStatusCodes.has(error.code) ? 'request' : 'engine')
  error.rookieCode = details?.rookieCode ?? null
  error.stopReason = details?.stopReason ?? null
  error.profileIds = Array.isArray(details?.profileIds) ? details.profileIds : []
  error.sourceKind = details?.sourceKind ?? null
  error.targetOs = details?.targetOs ?? null
  error.pathRedacted = details?.pathRedacted ?? false
  error.required = Array.isArray(details?.required) ? details.required : []
  return error
}

function asyncNative(nativeFunction, name) {
  requiredNative(nativeFunction, name)
  return (...args) => {
    try {
      return Promise.resolve(nativeFunction(...args)).catch((error) => {
        throw decorateNativeError(error)
      })
    } catch (error) {
      return Promise.reject(decorateNativeError(error))
    }
  }
}

const chromiumPathOptionKeys = new Set([
  'domains',
  'browserId',
  'localStatePath',
  'plaintextOnly',
  'appBound',
])

function validateChromiumPathOptions(options) {
  if (options === null || options === undefined) {
    return undefined
  }
  if (typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Chromium path options must be an object or null')
  }
  const prototype = Object.getPrototypeOf(options)
  if (prototype !== null && Object.getPrototypeOf(prototype) !== null) {
    throw new TypeError('Chromium path options must be a plain object or null')
  }
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !chromiumPathOptionKeys.has(key)) {
      throw new TypeError(
        'Unknown Chromium path option: ' + (typeof key === 'symbol' ? key.toString() : key)
      )
    }
  }

  const normalized = {}
  const hasOwn = (key) => Object.prototype.hasOwnProperty.call(options, key)
  if (hasOwn('domains') && options.domains !== null && options.domains !== undefined) {
    if (!Array.isArray(options.domains)) {
      throw new TypeError('Chromium path option domains must be an array of strings or null')
    }
    for (const [index, domain] of options.domains.entries()) {
      if (typeof domain !== 'string') {
        throw new TypeError(
          'Chromium path option domains element ' + index + ' must be a string'
        )
      }
    }
    normalized.domains = options.domains.slice()
  }

  for (const key of ['browserId', 'localStatePath', 'appBound']) {
    if (!hasOwn(key)) {
      continue
    }
    const value = options[key]
    if (value !== null && value !== undefined) {
      if (typeof value !== 'string') {
        throw new TypeError('Chromium path option ' + key + ' must be a string or null')
      }
      normalized[key] = value
    }
  }

  if (
    hasOwn('plaintextOnly')
    && options.plaintextOnly !== null
    && options.plaintextOnly !== undefined
  ) {
    if (typeof options.plaintextOnly !== 'boolean') {
      throw new TypeError('Chromium path option plaintextOnly must be a boolean or null')
    }
    normalized.plaintextOnly = options.plaintextOnly
  }

  const selectorCount = Number(normalized.browserId !== undefined)
    + Number(normalized.localStatePath !== undefined)
    + Number(normalized.plaintextOnly === true)
  if (selectorCount > 1) {
    throw new TypeError(
      'Chromium path options browserId, localStatePath, and plaintextOnly are mutually exclusive'
    )
  }
  return normalized
}

function chromiumPathNative(nativeFunction, name) {
  const required = requiredNative(nativeFunction, name)
  return asyncNative(
    (path, options, timeoutMs, cancellation) =>
      required(path, validateChromiumPathOptions(options), timeoutMs, cancellation),
    name
  )
}

// The canonical flat path-extract job. Its options bundle \`timeoutMs\` as a
// field (unlike the deprecated \`chromiumPathNative\` family, where it is its
// own positional parameter), so it needs its own key set and validator rather
// than reusing \`validateChromiumPathOptions\`.
const extractFromPathOptionKeys = new Set([
  'domains',
  'browserId',
  'localStatePath',
  'plaintextOnly',
  'timeoutMs',
  'appBound',
])

const MAX_TIMEOUT_MS = 4294967295

// N-API coerces whatever JS number it is given into the native \`u32\` field, so
// -1, NaN, Infinity, and fractional values do not fail -- they silently become
// some other deadline than the one that was asked for. A rejected request is
// the honest answer; a 4294967295 ms timeout from \`timeoutMs: -1\` is not.
function validateTimeoutMs(value, functionName) {
  if (
    typeof value !== 'number'
    || !Number.isInteger(value)
    || value < 0
    || value > MAX_TIMEOUT_MS
  ) {
    throw new TypeError(
      \`\${functionName} option timeoutMs must be an integer between 0 and \${MAX_TIMEOUT_MS}, or null\`
    )
  }
  return value
}

function validateExtractFromPathOptions(options) {
  if (options === null || options === undefined) {
    return undefined
  }
  if (typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('extractFromPath options must be an object or null')
  }
  const prototype = Object.getPrototypeOf(options)
  if (prototype !== null && Object.getPrototypeOf(prototype) !== null) {
    throw new TypeError('extractFromPath options must be a plain object or null')
  }
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !extractFromPathOptionKeys.has(key)) {
      throw new TypeError(
        'Unknown extractFromPath option: ' + (typeof key === 'symbol' ? key.toString() : key)
      )
    }
  }

  const normalized = {}
  const hasOwn = (key) => Object.prototype.hasOwnProperty.call(options, key)
  if (hasOwn('domains') && options.domains !== null && options.domains !== undefined) {
    if (!Array.isArray(options.domains)) {
      throw new TypeError('extractFromPath option domains must be an array of strings or null')
    }
    for (const [index, domain] of options.domains.entries()) {
      if (typeof domain !== 'string') {
        throw new TypeError('extractFromPath option domains element ' + index + ' must be a string')
      }
    }
    normalized.domains = options.domains.slice()
  }

  for (const key of ['browserId', 'localStatePath', 'appBound']) {
    if (!hasOwn(key)) {
      continue
    }
    const value = options[key]
    if (value !== null && value !== undefined) {
      if (typeof value !== 'string') {
        throw new TypeError('extractFromPath option ' + key + ' must be a string or null')
      }
      normalized[key] = value
    }
  }

  if (
    hasOwn('plaintextOnly')
    && options.plaintextOnly !== null
    && options.plaintextOnly !== undefined
  ) {
    if (typeof options.plaintextOnly !== 'boolean') {
      throw new TypeError('extractFromPath option plaintextOnly must be a boolean or null')
    }
    normalized.plaintextOnly = options.plaintextOnly
  }

  if (hasOwn('timeoutMs') && options.timeoutMs !== null && options.timeoutMs !== undefined) {
    normalized.timeoutMs = validateTimeoutMs(options.timeoutMs, 'extractFromPath')
  }

  const selectorCount = Number(normalized.browserId !== undefined)
    + Number(normalized.localStatePath !== undefined)
    + Number(normalized.plaintextOnly === true)
  if (selectorCount > 1) {
    throw new TypeError(
      'extractFromPath options browserId, localStatePath, and plaintextOnly are mutually exclusive'
    )
  }
  return normalized
}

function extractFromPathNative(nativeFunction, name) {
  const required = requiredNative(nativeFunction, name)
  return asyncNative(
    (path, options, cancellation) =>
      required(path, validateExtractFromPathOptions(options), cancellation),
    name
  )
}

function unsupportedPlatform(name, supportedPlatform) {
  return () => Promise.reject(new Error(
    \`\${name} is only available on \${supportedPlatform}; current platform is \${platform}\`
  ))
}

function platformNative(nativeFunction, name, nodePlatforms, supportedPlatform) {
  const supported = Array.isArray(nodePlatforms) ? nodePlatforms : [nodePlatforms]
  if (supported.includes(platform)) {
    requiredNative(nativeFunction, name)
    return asyncNative(nativeFunction, name)
  }
  return asyncNative(unsupportedPlatform(name, supportedPlatform), name)
}

module.exports.CancellationHandle = requiredNative(CancellationHandle, 'CancellationHandle')
module.exports.version = requiredNative(version, 'version')
module.exports.toNetscape = requiredNative(toNetscape, 'toNetscape')
module.exports.anyBrowser = asyncNative(anyBrowser, 'anyBrowser')
module.exports.extractFromPath = extractFromPathNative(extractFromPath, 'extractFromPath')
module.exports.cookiesFromPath = asyncNative(cookiesFromPath, 'cookiesFromPath')
module.exports.chromiumCookiesFromPath = chromiumPathNative(chromiumCookiesFromPath, 'chromiumCookiesFromPath')
module.exports.chromiumCookiesFromPathDetailed = chromiumPathNative(chromiumCookiesFromPathDetailed, 'chromiumCookiesFromPathDetailed')
module.exports.firefox = asyncNative(firefox, 'firefox')
module.exports.zen = asyncNative(zen, 'zen')
module.exports.librewolf = asyncNative(librewolf, 'librewolf')
${platformNativeExportLine('cachy')}
module.exports.chrome = asyncNative(chrome, 'chrome')
module.exports.brave = asyncNative(brave, 'brave')
module.exports.arc = asyncNative(arc, 'arc')
module.exports.edge = asyncNative(edge, 'edge')
module.exports.opera = asyncNative(opera, 'opera')
${platformNativeExportLine('operaGx')}
module.exports.chromium = asyncNative(chromium, 'chromium')
module.exports.vivaldi = asyncNative(vivaldi, 'vivaldi')
module.exports.load = asyncNative(load, 'load')
${platformNativeExportLine('octoBrowser')}
${platformNativeExportLine('internetExplorer')}
${platformNativeExportLine('safari')}
module.exports.chromiumBased = asyncNative(chromiumBased, 'chromiumBased')
module.exports.chromiumBasedDetailed = asyncNative(chromiumBasedDetailed, 'chromiumBasedDetailed')
module.exports.firefoxProfiles = asyncNative(firefoxProfiles, 'firefoxProfiles')
module.exports.firefoxProfile = asyncNative(firefoxProfile, 'firefoxProfile')
module.exports.chromeProfiles = asyncNative(chromeProfiles, 'chromeProfiles')
module.exports.chromeProfile = asyncNative(chromeProfile, 'chromeProfile')
module.exports.firefoxBased = asyncNative(firefoxBased, 'firefoxBased')
module.exports.firefoxBasedDetailed = asyncNative(firefoxBasedDetailed, 'firefoxBasedDetailed')
module.exports.supportedBrowsers = asyncNative(supportedBrowsers, 'supportedBrowsers')
module.exports.browserProfiles = asyncNative(browserProfiles, 'browserProfiles')
module.exports.browserReport = asyncNative(browserReport, 'browserReport')
module.exports.loadReport = asyncNative(loadReport, 'loadReport')
module.exports.ReadResult = requiredNative(ReadResult, 'ReadResult')
module.exports.read = asyncNative(read, 'read')
module.exports.jar = asyncNative(jar, 'jar')
module.exports.profiles = asyncNative(profiles, 'profiles')
module.exports.report = asyncNative(report, 'report')
module.exports.fromPath = asyncNative(fromPath, 'fromPath')

if (testWorkerPanic) {
  module.exports.__testWorkerPanic = asyncNative(testWorkerPanic, 'testWorkerPanic')
}
`

writeFileSync(loaderPath, loader)

let types = readFileSync(typesPath, 'utf8')

// napi-rs v3 emits aliases for the Rust identifiers even when `js_name`
// supplies the public class names. They are types only (the patched runtime
// facade intentionally does not export them), so remove the aliases to keep
// the declaration surface aligned with the actual package exports.
types = types.replace(/^export type Js(?:CancellationHandle|ReadResult) = .*\n\n?/gm, '')

// Whether `types` is napi's own fresh output (the only case that can be
// trusted to reflect this build's actual #[cfg(...)] gates) or a *previously
// patched* file being fed back in, e.g. by a test asserting patch-loader.js
// is idempotent on its own output. A prior patch run already stripped every
// legacy platform function's original declaration and replaced it with one
// unconditional copy per function under the facade marker, for every
// platform regardless of what this build compiled -- so once that's
// happened, presence/absence in `types` no longer means anything about this
// build's #[cfg(...)] gates.
const isFreshNapiOutput = !types.includes('/** rookie-cookies cross-platform facade */')

const chromiumPathOptionsPattern = /^export interface ChromiumPathOptions \{\n(?:  .*\n)*\}/m
if (!chromiumPathOptionsPattern.test(types)) {
  throw new Error('patch-loader.js: generated declarations are missing ChromiumPathOptions')
}
types = types.replace(
  chromiumPathOptionsPattern,
  `export interface ChromiumPathOptions {
  domains?: string[] | null
  browserId?: string | null
  localStatePath?: string | null
  plaintextOnly?: boolean | null
  appBound?: AppBoundPolicy | null
}`
)

const canonicalDeclarationPatterns = [
  [
    /^export declare function cookiesFromPath\([^\n]*$/m,
    'export declare function cookiesFromPath(path: string, domains?: string[] | null, timeoutMs?: number | null, cancellation?: CancellationHandle | null): Promise<CookieObject[]>',
  ],
  [
    /^export declare function chromiumCookiesFromPath\([^\n]*$/m,
    'export declare function chromiumCookiesFromPath(path: string, options?: ChromiumPathOptions | null, timeoutMs?: number | null, cancellation?: CancellationHandle | null): Promise<CookieObject[]>',
  ],
  [
    /^export declare function chromiumCookiesFromPathDetailed\([^\n]*$/m,
    'export declare function chromiumCookiesFromPathDetailed(path: string, options?: ChromiumPathOptions | null, timeoutMs?: number | null, cancellation?: CancellationHandle | null): Promise<DetailedCookieObject[]>',
  ],
]
for (const [pattern, declaration] of canonicalDeclarationPatterns) {
  if (!pattern.test(types)) {
    throw new Error(`patch-loader.js: generated declarations are missing ${declaration}`)
  }
  types = types.replace(pattern, declaration)
}

// Two separate hazards need two separate checks, because one cannot cover the
// other: a baseline derived from the input can never notice that the input
// itself came up short.
//
//   1. The generated declarations arrive incomplete -- caught below by
//      requiring every function the export facade publishes to be declared.
//      The facade is this script's own list of what the package exports, so it
//      is an external floor rather than a restatement of the input.
//   2. Patching drops something on the way through -- caught after the rewrite
//      by comparing the surviving names against everything napi generated.
//      This one is structural: a declaration added later is covered without
//      anybody remembering to list it.
const declarationPattern = /^export (?:declare function|declare class|interface) (\w+)/gm
const generatedNames = new Set(
  [...types.matchAll(declarationPattern)].map((match) => match[1])
)
// Compiled only into the regression-test build and deliberately stripped below,
// so it is the one generated name that must not survive.
generatedNames.delete('testWorkerPanic')

// napi only generates these on the platform that owns them; the facade
// re-declares them for every platform, so they are absent from `generatedNames`
// on most builds and cannot be required of it.
// `chromiumBased`/`chromiumBasedDetailed` are not in browser_registry.json -- they are one
// deprecated function whose Rust signature itself differs by OS, not a registered browser --
// so they stay an explicit addendum to the registry-derived legacy browser functions.
const platformFunctions = [...Object.keys(LEGACY_PLATFORM_FUNCTIONS), 'chromiumBased', 'chromiumBasedDetailed']
const publishedFunctions = [...loader.matchAll(/^module\.exports\.(\w+) = /gm)]
  .map((match) => match[1])
  .filter((name) => !name.startsWith('__') && !platformFunctions.includes(name))
const undeclared = publishedFunctions.filter((name) => !generatedNames.has(name))
if (undeclared.length > 0) {
  throw new Error(
    `Generated declarations were truncated: missing ${undeclared.join(', ')}`
  )
}

// The registry-derived platform list only helps if it agrees with the actual
// `#[cfg(target_os = ...)]` gates in bindings/node/src/lib.rs -- both name the
// same platforms by hand, in different files. On fresh napi output,
// `generatedNames` is ground truth for what this build's #[cfg(...)] gates
// actually compiled; a mismatch here would otherwise surface at import time
// as a hard crash for every user on the affected platform (`platformNative`
// calls `requiredNative` eagerly), not just callers of the one drifted
// function. Runs only on fresh napi output that already passed the
// completeness check above: an already-patched file's facade re-declares
// every legacy platform function for every platform (making presence in
// `types` meaningless there), and a truncated file would make an unrelated
// omission look like a platform mismatch.
if (isFreshNapiOutput) {
  for (const functionName of Object.keys(LEGACY_PLATFORM_FUNCTIONS)) {
    const registryExpectsThisPlatform = legacyFunctionPlatforms[functionName].includes(
      process.platform,
    )
    const rustCompiledThisPlatform = generatedNames.has(functionName)
    if (registryExpectsThisPlatform !== rustCompiledThisPlatform) {
      throw new Error(
        `patch-loader.js: '${functionName}' disagrees with bindings/node/src/lib.rs on ${process.platform} -- ` +
          `browser_registry.json says it ${registryExpectsThisPlatform ? 'should' : 'should not'} be compiled here, ` +
          `but the Rust #[cfg(...)] gate ${rustCompiledThisPlatform ? 'compiled' : 'did not compile'} it. ` +
          'Keep browser_registry.json and the #[cfg(...)] gate in sync.',
      )
    }
  }
}

// napi-rs sees every `appBound`/`resource`/`method` field as a plain
// `Option<String>` and has no way to express our JS-facing string-literal
// unions from the Rust side; retype every generated occurrence to the real
// union below instead. `appBound` appears on both non-nullable
// (`ReadOptions`, ...) and `use_nullable` (`ChromiumPathOptions`) structs, so
// the trailing `| null` is optional and preserved when present.
types = types.replace(
  /^(\s*)appBound\?: string( \| null)?$/gm,
  '$1appBound?: AppBoundPolicy$2',
)
types = types.replace(
  /^(\s*)resource\?: string( \| null)?$/gm,
  '$1resource?: ResourceKind$2',
)
types = types.replace(/^(\s*)method\?: string( \| null)?$/gm, '$1method?: MethodClass$2')

function retypeSelect(interfaceName, literalType) {
  const start = types.indexOf(`export interface ${interfaceName} {`)
  if (start === -1) {
    throw new Error(`patch-loader.js: generated declarations are missing ${interfaceName}`)
  }
  const end = types.indexOf('\n}', start)
  const original = types.slice(start, end)
  const plain = '  select?: string'
  const typed = `  select?: ${literalType}`
  if (!original.includes(plain) && !original.includes(typed)) {
    throw new Error(`patch-loader.js: ${interfaceName}.select has an unexpected generated type`)
  }
  const replacement = original.replace(plain, typed)
  types = types.slice(0, start) + replacement + types.slice(end)
}

retypeSelect('ReadOptions', "'legacy_first'")
retypeSelect('ReportOptions', "'legacy_first' | 'all'")

// NAPI-RS emits declarations for the platform doing the build. Remove only
// those platform-specific functions and append the cross-platform facade.
// Keeping the rest of the generated file intact is load-bearing: slicing at a
// common declaration such as `load` silently discarded APIs generated after
// it, including firefoxProfiles and firefoxProfile. Retype generated
// interfaces before this cut so the declaration-loss check below, rather than
// an unrelated type rewrite, diagnoses an accidentally early marker.
const facadeMarker = '/** rookie-cookies cross-platform facade */'
const facadeIndex = types.indexOf(facadeMarker)
if (facadeIndex !== -1) {
  types = types.slice(0, facadeIndex)
}

types = types.replace(
  /^\/\*\* @deprecated Use `(?:extractFromPath|fromPath\(\.\.\.\)\.detailedCookies)`\. Earliest removal is 0\.7\. \*\/\n(?=export declare function chromiumBased)/gm,
  ''
)
types = types.replace(
  /^export declare function (?:cachy|operaGx|octoBrowser|internetExplorer|safari|chromiumBased|chromiumBasedDetailed|testWorkerPanic)\([^\n]*\):[^\n]*\n?/gm,
  ''
)
types = types.replace(
  /^\/\*\* (?:Windows-only browsers|macOS-only browsers|Unix browsers|Windows browsers) \*\/\n?/gm,
  ''
)
// napi-rs v3 leaves a different number of blank lines where target-gated
// declarations were omitted or removed. Collapse those gaps so Linux, macOS,
// and Windows regenerate the same committed declaration file byte-for-byte.
types = types.replace(/\n{3,}/g, '\n\n')

types = types.trimEnd()
types += `
${facadeMarker}
export type AppBoundPolicy = 'disabled' | 'injection_only' | 'allow_elevated_fallback'
export type ResourceKind = 'navigation' | 'subresource'
export type MethodClass = 'safe' | 'unsafe'
// napi-rs v2 generated these public aliases; retain them across the v3
// generator migration so existing TypeScript imports remain source-compatible.
export type JsCancellationHandle = CancellationHandle
export type JsReadResult = ReadResult
/** Structured diagnostics attached to errors rejected by facade operations. */
export interface RookieError extends Error {
  kind: 'request' | 'stopped' | 'source' | 'engine'
  code?: string
  rookieCode: string | null
  /** Current values are timed_out, cancelled, and resource_exhausted; open for future reasons. */
  stopReason: string | null
  profileIds: string[]
  sourceKind: string | null
  targetOs: string | null
  pathRedacted: boolean
  /** The SendContext selectors incomplete_send_context says are missing. Empty otherwise. */
  required: string[]
}
${legacyPlatformDeclarations()}
/** Unix browsers */
/** @deprecated Use extractFromPath. Earliest removal is 0.7. */
export declare function chromiumBased(dbPath: string, domains?: Array<string> | undefined | null, browserId?: string | undefined | null): Promise<Array<CookieObject>>
/** @deprecated Use fromPath(...).detailedCookies. Earliest removal is 0.7. */
export declare function chromiumBasedDetailed(dbPath: string, domains?: Array<string> | undefined | null, browserId?: string | undefined | null): Promise<Array<DetailedCookieObject>>
/** Windows browsers */
/** @deprecated Use extractFromPath. Earliest removal is 0.7. */
export declare function chromiumBased(keyPath: string, dbPath: string, domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
/** @deprecated Use fromPath(...).detailedCookies. Earliest removal is 0.7. */
export declare function chromiumBasedDetailed(keyPath: string, dbPath: string, domains?: Array<string> | undefined | null): Promise<Array<DetailedCookieObject>>
`

// Everything napi generated must still be declared. The platform-specific
// functions were stripped above and re-added by the facade, so they are
// expected to reappear rather than to have survived in place.
const survivors = new Set(
  [...types.matchAll(declarationPattern)].map((match) => match[1])
)
const dropped = [...generatedNames].filter((name) => !survivors.has(name))
if (dropped.length > 0) {
  throw new Error(`Patching dropped generated declarations: ${dropped.join(', ')}`)
}
if (survivors.has('testWorkerPanic')) {
  throw new Error('patch-loader.js: testWorkerPanic must not reach the published declarations')
}

writeFileSync(typesPath, types)
