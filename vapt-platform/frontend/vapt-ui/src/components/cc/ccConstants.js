export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
export const SEV_HEX = { critical: 0xff6b6b, high: 0xff9f5a, medium: 0xf5d76e, low: 0x8a99ab, info: 0x4f6378 };

export const CRIT_HEX = { critical: 0xff6b6b, high: 0xff9f5a, medium: 0xf5d76e, low: 0x8a99ab };
export const ENV_ORDER = ["production", "staging", "development", "test", "other"];

export const normalizeEnv = (value) => {
  const v = String(value || "").toLowerCase();
  if (v.startsWith("prod")) return "production";
  if (v.startsWith("stag")) return "staging";
  if (v.startsWith("dev")) return "development";
  if (v.startsWith("test") || v === "qa") return "test";
  return "other";
};

export const normalizeCrit = (value) => {
  const v = String(value || "").toLowerCase();
  return CRIT_HEX[v] !== undefined ? v : "medium";
};

export const isExternal = (asset) =>
  String(asset.classification || "").toLowerCase() === "external" || String(asset.exposure || "").toLowerCase() === "external";

export const isManaged = (asset) =>
  (asset.tags || []).some((t) => String(t).includes("managed") || String(t).includes("agent")) ||
  String(asset.asset_type || "").toLowerCase().includes("endpoint");
