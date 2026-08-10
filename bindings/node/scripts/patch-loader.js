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

loader = loader.replace(
  /^const \{ version,.* \} = nativeBinding$/m,
  'const { version, anyBrowser, firefox, zen, librewolf, chrome, brave, arc, edge, opera, operaGx, chromium, vivaldi, firefoxBased, load, octoBrowser, internetExplorer, safari, chromiumBased } = nativeBinding'
)

if (!loader.includes('function unsupportedPlatform(')) {
  loader = loader.replace(
    'module.exports.version = version',
    `function unsupportedPlatform(name, supportedPlatform) {
  return () => {
    throw new Error(
      \`\${name} is only available on \${supportedPlatform}; current platform is \${platform}\`
    )
  }
}

module.exports.version = version`
  )
}

loader = loader.replace(
  /^module\.exports\.(?:octoBrowser|internetExplorer|safari|chromiumBased) = .*\n?/gm,
  ''
)
loader = loader.replace(
  'module.exports.load = load\n',
  `module.exports.load = load
module.exports.octoBrowser = octoBrowser || unsupportedPlatform('octoBrowser', 'Windows')
module.exports.internetExplorer = internetExplorer || unsupportedPlatform('internetExplorer', 'Windows')
module.exports.safari = safari || unsupportedPlatform('safari', 'macOS')
module.exports.chromiumBased = chromiumBased
`
)

writeFileSync(loaderPath, loader)

let types = readFileSync(typesPath, 'utf8')
const loadDeclaration = 'export declare function load(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>\n'
const loadIndex = types.indexOf(loadDeclaration)
if (loadIndex === -1) {
  throw new Error(`Could not find the load declaration in ${typesPath}`)
}

types = types.slice(0, loadIndex + loadDeclaration.length)
types += `/** Windows-only browsers */
export declare function octoBrowser(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
export declare function internetExplorer(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
/** macOS-only browsers */
export declare function safari(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
/** Unix browsers */
export declare function chromiumBased(dbPath: string, domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
/** Windows browsers */
export declare function chromiumBased(keyPath: string, dbPath: string, domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>
`

writeFileSync(typesPath, types)
