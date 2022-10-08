import { TOTPSettings, VariantType } from "./types";

/**
 * decode OTP Auth URI and returns TOTP settings
 * @param uri OTPAuth URI
 * @returns
 */
export const decodeOtpAuthUri = (uri: string) => {
  uri = uri.trim();
  const minLen = 14;
  if (uri.length < minLen || uri.slice(0, minLen) !== "otpauth://totp")
    throw new Error("Invalid URI format");

  const paramIdx = uri.search(/\?/);
  const params = new URLSearchParams(uri.slice(paramIdx));

  const shaDict = {
    SHA1: "SHA-1",
    SHA256: "SHA-256",
    SHA512: "SHA-512",
  };

  type shaDictKeys = "SHA1" | "SHA256" | "SHA512";

  const algorithm = shaDict[(params.get("algorithm") || "SHA1") as shaDictKeys];

  const res: TOTPSettings = {
    secret: params.get("secret") || "",
    variant: algorithm as VariantType,
  };

  return res;
};
