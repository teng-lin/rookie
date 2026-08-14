const { readFileSync, writeFileSync } = require('fs')
const { join } = require('path')

const root = join(__dirname, '..')
const loaderPath = join(root, 'index.js')
const typesPath = join(root, 'index.d.ts')

let loader = readFileSync(loaderPath, 'utf8')

if (!loader.includes("const { optionalDependencies = {} } = require('./package.json')")) {
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

const nativeBindingDestructurePattern = /^const \{ version,.* \} = nativeBinding$/m
if (!nativeBindingDestructurePattern.test(loader)) {
  throw new Error(
    "patch-loader.js: could not find the napi-generated `const { version, ... } = nativeBinding` line; napi-rs output format may have changed"
  )
}
loader = loader.replace(
  nativeBindingDestructurePattern,
  'const { version, toNetscape, anyBrowser, firefox, firefoxProfiles, firefoxProfile, zen, librewolf, chrome, chromeProfiles, chromeProfile, brave, arc, edge, opera, operaGx, chromium, vivaldi, firefoxBased, supportedBrowsers, browserProfiles, browserReport, loadReport, load, octoBrowser, internetExplorer, safari, chromiumBased, testWorkerPanic } = nativeBinding'
)

const exportStart = loader.search(
  /^(?:function (?:requiredNative|asyncNative|unsupportedPlatform|platformNative)\(|module\.exports\.version = version)/m
)
if (exportStart === -1) {
  throw new Error('Generated loader has no export facade')
}

loader = loader.slice(0, exportStart)
loader += `function requiredNative(nativeFunction, name) {
  if (typeof nativeFunction !== 'function') {
    throw new TypeError(\`Expected a native binding function: \${name}\`)
  }
  return nativeFunction
}

function asyncNative(nativeFunction, name) {
  requiredNative(nativeFunction, name)
  return (...args) => {
    try {
      return Promise.resolve(nativeFunction(...args))
    } catch (error) {
      return Promise.reject(error)
    }
  }
}

function unsupportedPlatform(name, supportedPlatform) {
  return () => Promise.reject(new Error(
    \`\${name} is only available on \${supportedPlatform}; current platform is \${platform}\`
  ))
}

function platformNative(nativeFunction, name, nodePlatform, supportedPlatform) {
  if (typeof nativeFunction === 'function') {
    return asyncNative(nativeFunction, name)
  }
  if (platform === nodePlatform) {
    requiredNative(nativeFunction, name)
  }
  return asyncNative(unsupportedPlatform(name, supportedPlatform), name)
}

module.exports.version = requiredNative(version, 'version')
module.exports.toNetscape = requiredNative(toNetscape, 'toNetscape')
module.exports.anyBrowser = asyncNative(anyBrowser, 'anyBrowser')
module.exports.firefox = asyncNative(firefox, 'firefox')
module.exports.zen = asyncNative(zen, 'zen')
module.exports.librewolf = asyncNative(librewolf, 'librewolf')
module.exports.chrome = asyncNative(chrome, 'chrome')
module.exports.brave = asyncNative(brave, 'brave')
module.exports.arc = asyncNative(arc, 'arc')
module.exports.edge = asyncNative(edge, 'edge')
module.exports.opera = asyncNative(opera, 'opera')
module.exports.operaGx = asyncNative(operaGx, 'operaGx')
module.exports.chromium = asyncNative(chromium, 'chromium')
module.exports.vivaldi = asyncNative(vivaldi, 'vivaldi')
module.exports.load = asyncNative(load, 'load')
module.exports.octoBrowser = platformNative(octoBrowser, 'octoBrowser', 'win32', 'Windows')
module.exports.internetExplorer = platformNative(internetExplorer, 'internetExplorer', 'win32', 'Windows')
module.exports.safari = platformNative(safari, 'safari', 'darwin', 'macOS')
module.exports.chromiumBased = asyncNative(chromiumBased, 'chromiumBased')
module.exports.firefoxProfiles = asyncNative(firefoxProfiles, 'firefoxProfiles')
module.exports.firefoxProfile = asyncNative(firefoxProfile, 'firefoxProfile')
module.exports.chromeProfiles = asyncNative(chromeProfiles, 'chromeProfiles')
module.exports.chromeProfile = asyncNative(chromeProfile, 'chromeProfile')
module.exports.firefoxBased = asyncNative(firefoxBased, 'firefoxBased')
module.exports.supportedBrowsers = asyncNative(supportedBrowsers, 'supportedBrowsers')
module.exports.browserProfiles = asyncNative(browserProfiles, 'browserProfiles')
module.exports.browserReport = asyncNative(browserReport, 'browserReport')
module.exports.loadReport = asyncNative(loadReport, 'loadReport')

if (testWorkerPanic) {
  module.exports.__testWorkerPanic = asyncNative(testWorkerPanic, 'testWorkerPanic')
}
`

writeFileSync(loaderPath, loader)

let types = readFileSync(typesPath, 'utf8')

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
const declarationPattern = /^export (?:declare function|interface) (\w+)/gm
const generatedNames = new Set(
  [...types.matchAll(declarationPattern)].map((match) => match[1])
)
// Compiled only into the regression-test build and deliberately stripped below,
// so it is the one generated name that must not survive.
generatedNames.delete('testWorkerPanic')

// napi only generates these on the platform that owns them; the facade
// re-declares them for every platform, so they are absent from `generatedNames`
// on most builds and cannot be required of it.
const platformFunctions = ['octoBrowser', 'internetExplorer', 'safari', 'chromiumBased']
const publishedFunctions = [...loader.matchAll(/^module\.exports\.(\w+) = /gm)]
  .map((match) => match[1])
  .filter((name) => !name.startsWith('__') && !platformFunctions.includes(name))
const undeclared = publishedFunctions.filter((name) => !generatedNames.has(name))
if (undeclared.length > 0) {
  throw new Error(
    `Generated declarations were truncated: missing ${undeclared.join(', ')}`
  )
}

// NAPI-RS emits declarations for the platform doing the build. Remove only
// those platform-specific functions and append the cross-platform facade.
// Keeping the rest of the generated file intact is load-bearing: slicing at a
// common declaration such as `load` silently discarded APIs generated after
// it, including firefoxProfiles and firefoxProfile.
const facadeMarker = '/** rookie-cookies cross-platform facade */'
const facadeIndex = types.indexOf(facadeMarker)
if (facadeIndex !== -1) {
  types = types.slice(0, facadeIndex)
}

types = types.replace(
  /^export declare function (?:octoBrowser|internetExplorer|safari|chromiumBased|testWorkerPanic)\([^\n]*\):[^\n]*\n?/gm,
  ''
)
types = types.replace(
  /^\/\*\* (?:Windows-only browsers|macOS-only browsers|Unix browsers|Windows browsers) \*\/\n?/gm,
  ''
)

types = types.trimEnd()
types += `
${facadeMarker}
/** Windows-only browsers */
export declare function octoBrowser(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
export declare function internetExplorer(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
/** macOS-only browsers */
export declare function safari(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
/** Unix browsers */
export declare function chromiumBased(dbPath: string, domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
/** Windows browsers */
export declare function chromiumBased(keyPath: string, dbPath: string, domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
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
