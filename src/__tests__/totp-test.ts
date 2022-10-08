import { calcTOTP } from "../totp";
import { AlgorithmType } from "../types";

// test vector is from https://www.rfc-editor.org/rfc/rfc6238#appendix-B
const secret = "12345678901234567890";
const secret32 = secret.repeat(2).slice(0, 32);
const secret64 = secret.repeat(4).slice(0, 64);
const testVector: { T: string; mode: AlgorithmType; expect: string }[] = [
  {
    T: "0000000000000001",
    mode: "SHA-1",
    expect: "94287082",
  },
  {
    T: "0000000000000001",
    mode: "SHA-256",
    expect: "46119246",
  },
  {
    T: "0000000000000001",
    mode: "SHA-512",
    expect: "90693936",
  },
  {
    T: "00000000023523EC",
    mode: "SHA-1",
    expect: "07081804",
  },
  {
    T: "00000000023523EC",
    mode: "SHA-256",
    expect: "68084774",
  },
  {
    T: "00000000023523EC",
    mode: "SHA-512",
    expect: "25091201",
  },
  {
    T: "00000000023523ED",
    mode: "SHA-1",
    expect: "14050471",
  },
  {
    T: "00000000023523ED",
    mode: "SHA-256",
    expect: "67062674",
  },
  {
    T: "00000000023523ED",
    mode: "SHA-512",
    expect: "99943326",
  },
  {
    T: "000000000273EF07",
    mode: "SHA-1",
    expect: "89005924",
  },
  {
    T: "000000000273EF07",
    mode: "SHA-256",
    expect: "91819424",
  },
  {
    T: "000000000273EF07",
    mode: "SHA-512",
    expect: "93441116",
  },
  {
    T: "0000000003F940AA",
    mode: "SHA-1",
    expect: "69279037",
  },
  {
    T: "0000000003F940AA",
    mode: "SHA-256",
    expect: "90698825",
  },
  {
    T: "0000000003F940AA",
    mode: "SHA-512",
    expect: "38618901",
  },
  {
    T: "0000000027BC86AA",
    mode: "SHA-1",
    expect: "65353130",
  },
  {
    T: "0000000027BC86AA",
    mode: "SHA-256",
    expect: "77737706",
  },
  {
    T: "0000000027BC86AA",
    mode: "SHA-512",
    expect: "47863826",
  },
];

test("totpGenerate test", () => {
  const encoder = new TextEncoder();
  testVector.forEach((vec) => {
    let s = "";
    if (vec.mode == "SHA-1") s = secret;
    if (vec.mode == "SHA-256") s = secret32;
    if (vec.mode == "SHA-512") s = secret64;
    expect(
      calcTOTP(encoder.encode(secret), parseInt(vec.T, 16), 8, vec.mode)
    ).toBe(vec.expect);
  });
});
