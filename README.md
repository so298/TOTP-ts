# TOTP-ts

A TypeScript implementation of RFC6238

## examples

```typescript
import { decodeOtpAuthUri, getTOTP } from ".";
import { base32ToU8Array } from "./base32";

const time = new Date().getTime() / 1000;

// otpauth://totp/The%20University%20of%20Tokyo%3A8156892216%40utac.u-tokyo.ac.jp?secret=aaaaaaaa&issuer=Microsoft
let decoder = new TextDecoder();

const params = decodeOtpAuthUri(
  "otpauth://totp/hello:world?secret=aaaaaaaa&issuer=so298"
);

console.log(getTOTP(base32ToU8Array(params.secret), time));
```