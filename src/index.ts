import { base32ToU8Array } from "./base32";
import { generateTOTPWithTime } from "./totp";
import { decodeOtpAuthUri } from "./uri";

export const generateTOTPFromUri = (uri: string) => {
  const params = decodeOtpAuthUri(uri);
  const time = new Date().getTime() / 1000;
  const key = base32ToU8Array(params.secret);

  return generateTOTPWithTime(key, time, { algorithm: params.variant });
};

export default generateTOTPFromUri;
