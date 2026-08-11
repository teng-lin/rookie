# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie-cookies)

Browser extraction functions return Promises and must be awaited. When migrating
from v0.5.7 or earlier, add `await` (or use `.then(...)`) for every extraction
call. `version()` remains synchronous.

## Usage

```typescript
import { chrome } from "rookie-cookies";

const cookies = await chrome();
for (const cookie of cookies) {
  console.log(cookie);
}
```

## Firefox profiles

```typescript
import { firefoxProfile, firefoxProfiles } from "rookie-cookies";

for (const profile of await firefoxProfiles()) {
  console.log(profile.name, profile.path, profile.isDefault);
}

const cookies = await firefoxProfile("work", ["example.com"]);
```

## Netscape export

```typescript
import { chrome, toNetscape } from "rookie-cookies";

const output = toNetscape(await chrome());
```

The serializer prevents extra columns or forged records by encoding tabs,
carriage returns, and line feeds in cookie-controlled fields as `%09`, `%0D`,
and `%0A`. Every other character is preserved.
