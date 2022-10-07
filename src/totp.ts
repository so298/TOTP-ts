/**
 * implementation of RFC-6238
 * https://www.rfc-editor.org/rfc/rfc6238.html
 */
import jsSHA from "jssha";
const timeLen = 16;

export type VariantType = "SHA-1" | "SHA-256" | "SHA-512";

const keyLenDict = {
  "SHA-1": 20,
  "SHA-256": 32,
  "SHA-512": 64,
};

/**
 *  reference: https://www.rfc-editor.org/rfc/rfc6238#appendix-A
 *
 * @param key the shared secret
 * @param time a value that reflects a time
 * @param returnDigits number of digits to return
 * @param variant the crypto function to use
 * @returns a numeric String in base 10 that includes
 *              {@link truncationDigits} digits
 */
export const totp = (
  key: string,
  time: string,
  returnDigits: number,
  variant: VariantType
) => {
  if (time.length < timeLen) {
    time = "0".repeat(timeLen - time.length) + time;
  }

  const shaObj = new jsSHA(variant, "HEX");

  const keyLength = keyLenDict[variant];
  if (key.length != keyLength) key = key.repeat(keyLength).slice(0, keyLength);
  shaObj.setHMACKey(key, "TEXT", { encoding: "UTF8" });
  shaObj.update(time);
  const hash = shaObj.getHMAC("UINT8ARRAY");

  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  const otp = binary % Math.pow(10, returnDigits);

  let res = otp.toString();
  if (res.length < returnDigits)
    res = "0".repeat(returnDigits - res.length) + res;

  return res;
};
