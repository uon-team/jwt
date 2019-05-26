# JWT

A simple library to encode, decode and verify JWTs.

NOTE: No browser support yet. Works on node.js apps only because of 'crypto' and Buffer dependencies.

## Installation

```shell
    npm i @uon/jwt
```


## Usage

```typescript

import { Encode, Decode, Verify, JwtToken, VerifyResult } from '@uon/jwt';


const payload = {
    hello: 'world',
    iat: Date.now(),
    exp: Date.now() + 60 * 1000
};

// encode a payload to jwt string
const token_str = Encode(payload, 'my-secret', 'HS256');


// verify a token
const verify_result: VerifyResult = Verify(token_str, 'my-secret', { ... });
// verify_result.sig === true

// decode a token to its components
const token: JwtToken = Decode(token_str);

```

## Limitations
 - No support for payload encryption yet
