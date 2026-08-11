# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie-cookies)

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
