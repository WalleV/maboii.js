# maboii.js
amiibo™ encryption/decryption library.
This library is a port of the encryption/decryption code from [socram8888/amiitool](https://github.com/socram8888/amiitool).

## How to use
### Install the package
```bash
pnpm add maboii
```

### Load the keys
```js
import { loadMasterKeys } from 'maboii';

const keyResponse = await fetch('./keys.bin');
const keyBytes = new Uint8Array(await keyResponse.arrayBuffer());
const keys = loadMasterKeys(Array.from(keyBytes));
```

### Decrypt dump
```js
import { unpack } from 'maboii';

const dumpResponse = await fetch('./dumpFile.bin');
const dumpBuffer = new Uint8Array(await dumpResponse.arrayBuffer());
const unpackResult = await unpack(keys, Array.from(dumpBuffer));

// If decrypt is successful
if (unpackResult.result) {
    // The plain data is available through unpackResult.unpacked
}
```

### Encrypt plain data
```js
import { pack } from 'maboii';

const plainDumpResponse = await fetch('./dumpFile.dec.bin');
const plainDumpBuffer = new Uint8Array(await plainDumpResponse.arrayBuffer());
const packedResult = await pack(keys, Array.from(plainDumpBuffer));
```

### Use from Node.js
```js
import { readFile } from 'node:fs/promises';
import { loadMasterKeys, unpack } from 'maboii';

const keyBytes = await readFile(new URL('./keys.bin', import.meta.url));
const keys = loadMasterKeys([...keyBytes]);

const dumpBytes = await readFile(new URL('./dumpFile.bin', import.meta.url));
const { unpacked } = await unpack(keys, [...dumpBytes]);
```

### Read information from plain data
```js
import { plainDataUtils } from 'maboii';

// Let's read an Inkling dump
const plainDumpResponse = await fetch('./dumpFile.dec.bin');
const plainDumpBuffer = Array.from(new Uint8Array(await plainDumpResponse.arrayBuffer()));

plainDataUtils.getAmiiboId(plainDumpBuffer); // Returns '0800010003820002'
plainDataUtils.getCharacterId(plainDumpBuffer); // Returns '0800'
plainDataUtils.getGameSeriesId(plainDumpBuffer); // Returns '080'
plainDataUtils.getMiiName(plainDumpBuffer); // Returns the Mii name as string, in my case 'Holo' from my dump
plainDataUtils.getNickName(plainDumpBuffer); // Returns the amiibo™ name as string, in my case 'Sushy' from my dump
```

> **Note:** The library relies on the Web Crypto API. Modern browsers expose it in secure contexts (HTTPS), while Node.js 18 and newer expose the same API through `globalThis.crypto`. Older Node.js releases can still work as long as they provide `crypto.webcrypto`.

## Development

The project is bundled with [Rolldown](https://rolldown.rs/) and managed with [pnpm](https://pnpm.io/).

```bash
pnpm install
pnpm run build
```

The command above generates the browser-ready ESM bundle, the CommonJS build, and the accompanying TypeScript declaration files in `dist/`.

## Credits
- socram8888 - Author of amiitool
- AcK77 - Author of AmiiBomb which helped me a lot to test
