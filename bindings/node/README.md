# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie-cookies)

## Usage

```typescript
import { chrome } from "rookie-cookies";

const cookies = chrome();
for (const cookie of cookies) {
  console.log(cookie);
}
```
