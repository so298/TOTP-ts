import { generateTOTPFromUri } from "./";

const uri = 
  "otpauth://totp/hello:world?secret=aaaaaaaa&issuer=so298";

console.log(generateTOTPFromUri(uri));
