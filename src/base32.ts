const ACharCode = "A".charCodeAt(0);
const ZCharCode = "Z".charCodeAt(0);
const TwoCharCode = "2".charCodeAt(0);
const SevenCharCode = "7".charCodeAt(0);

const getBase32Val = (c: string) => {
  if (c.length != 1) throw new Error(`Invalid input "${c}"`);

  const charCode = c.charCodeAt(0);
  if (ACharCode <= charCode && charCode <= ZCharCode) {
    return charCode - ACharCode;
  }
  if (TwoCharCode <= charCode && charCode <= SevenCharCode) {
    return charCode - TwoCharCode + 26;
  }

  throw new Error(`Invalid input "${c}"`);
};

const base32ToBitsArray = (b: number) => {
  let ret = [];
  for (let i = 4; i >= 0; i--) {
    ret.push((b >> i) & 0x01);
  }
  return ret;
};

const bitsArrayToU8Array = (a: number[]) => {
  let byte = 0;
  let ret = [];
  for (let i = 0; i < a.length; i++) {
    let off = 7 - (i % 8);
    byte |= a[i] << off;
    if (off == 0) {
      ret.push(byte);
      byte = 0;
    }
  }

  if (a.length % 8 != 0) {
    ret.push(byte);
  }

  return new Uint8Array(ret);
};

export const base32ToU8Array = (str: string) => {
  str = str.toUpperCase();
  str = str.replace(/=+$/, "");

  let bitArr: number[] = [];
  for (let c of str) {
    let b = getBase32Val(c);
    bitArr = bitArr.concat(base32ToBitsArray(b));
  }

  return bitsArrayToU8Array(bitArr);
};
