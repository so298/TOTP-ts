# TOTP.ts

A TypeScript implementation of RFC6238
https://www.rfc-editor.org/rfc/rfc6238

## examples

An example is in `src/example.ts`

```typescript
import { generateTOTPFromUri } from "totp-ts";

const uri = 
  "otpauth://totp/hello:world?secret=aaaaaaaa&issuer=so298";

console.log(generateTOTPFromUri(uri));
```