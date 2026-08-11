# rookie-cookies JavaScript Docs

## Install

```console
npm install rookie-cookies
```

## Basic Usage

```js
import { brave } from "rookie-cookies";
const cookies = await brave();
```

Browser extraction functions return Promises and must be awaited. When migrating
from v0.5.7 or earlier, add `await` (or use `.then(...)`) for every extraction
call. `version()` remains synchronous.
