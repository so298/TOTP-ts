# TOTP-ts

A TypeScript implementation of RFC6238

## examples

```typescript
import { decodeOtpAuthUri, getTOTP } from ".";
import { base32ToU8Array } from "./base32";

const time = new Date().getTime() / 1000;

let decoder = new TextDecoder();

const params = decodeOtpAuthUri(
  "otpauth://totp/hello:world?secret=aaaaaaaa&issuer=so298"
);

console.log(getTOTP(base32ToU8Array(params.secret), time));
```