import { decodeOtpAuthUri } from "../totp";

test("OtpAuth URI decoding", () => {
  const uri =
    "otpauth://totp/foo:bar?secret=567890123456789&issuer=buz";
  expect(decodeOtpAuthUri(uri)).toStrictEqual({
    secret: "567890123456789",
    variant: "SHA-1",
  });
});
