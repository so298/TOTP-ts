export type VariantType = "SHA-1" | "SHA-256" | "SHA-512";

export type TOTPSettings = {
  secret: string;
  variant: VariantType;
};

export type TOTPOptions = {
  T0?: number;
  period?: number;
  algorithm?: VariantType ;
  digits?: number;
};
