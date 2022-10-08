import { decodeOtpAuthUri } from "../uri";

test("OtpAuth URI decoding", () => {
  const uri =
    "otpauth://totp/foo:bar?secret=567890123456789&issuer=buz";
  expect(decodeOtpAuthUri(uri)).toStrictEqual({
    secret: "567890123456789",
    options: {
      algorithm: "SHA-1"
    },
  });
});
