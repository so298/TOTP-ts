import { decodeOtpAuthUri } from "../";

test("OtpAuth URI decoding", () => {
  const uri =
    "otpauth://totp/The%20University%20of%20Tokyo%3A0123456789%40utac.u-tokyo.ac.jp?secret=567890123456789&issuer=Microsoft";
  expect(decodeOtpAuthUri(uri)).toStrictEqual({
    secret: "567890123456789",
    variant: "SHA-1",
  });
});
