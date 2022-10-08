export type AlgorithmType = "SHA-1" | "SHA-256" | "SHA-512";

export type DecodeURIReturn = {
  secret: string;
  options: TOTPOptions;
};

export type TOTPOptions = {
  T0?: number;
  period?: number;
  algorithm?: AlgorithmType;
  digits?: number;
};
