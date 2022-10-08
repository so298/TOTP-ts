import { getTOTP } from ".";

const time = (new Date()).getTime() / 1000;
console.log(getTOTP("\0\0\0\0\0", time));

// otpauth://totp/The%20University%20of%20Tokyo%3A8156892216%40utac.u-tokyo.ac.jp?secret=aaaaaaaa&issuer=Microsoft
let decoder = new TextDecoder();