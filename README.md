# TOTP.ts

A TypeScript implementation of RFC6238

## examples

Example is in `src/example.ts`

```typescript
import { generateTOTPFromUri } from "./";

const uri = 
  "otpauth://totp/hello:world?secret=aaaaaaaa&issuer=so298";

console.log(generateTOTPFromUri(uri));
```