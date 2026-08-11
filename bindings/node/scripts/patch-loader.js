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
  'const { version, toNetscape, anyBrowser, firefox, firefoxProfiles, firefoxProfile, zen, librewolf, chrome, brave, arc, edge, opera, operaGx, chromium, vivaldi, firefoxBased, load, octoBrowser, internetExplorer, safari, chromiumBased, testWorkerPanic } = nativeBinding'
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
module.exports.firefoxBased = asyncNative(firefoxBased, 'firefoxBased')

if (testWorkerPanic) {
  module.exports.__testWorkerPanic = asyncNative(testWorkerPanic, 'testWorkerPanic')
}
`

writeFileSync(loaderPath, loader)

let types = readFileSync(typesPath, 'utf8')

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

for (const declaration of [
  'export declare function toNetscape(',
  'export declare function firefoxProfiles(',
  'export declare function firefoxProfile('
]) {
  if (!types.includes(declaration)) {
    throw new Error(`Generated declarations were truncated: missing ${declaration}`)
  }
}

writeFileSync(typesPath, types)
