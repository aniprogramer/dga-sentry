/**
 * Client-side mirror of backend/src/domain_validation.py (the source of truth).
 * Same codes, same messages. Checked against shared/domain_cases.json.
 * The server never trusts this: it exists only for fast feedback.
 * PSL-based warnings (short, digit-heavy, private suffix...) come from the server response.
 */

export const MAX_DOMAIN_LEN = 253;
export const MAX_LABEL_LEN = 63;
export const MAX_RAW_LEN = 2048;
export const MAX_BATCH_SIZE = 100;

export const MESSAGES: Record<string, string> = {
  EMPTY: "Enter a domain name.",
  INVALID_CHARACTER: "Domain contains a character that is not allowed.",
  TOO_LONG: "Domain is longer than 253 characters.",
  LABEL_TOO_LONG: "A label is longer than 63 characters.",
  EMPTY_LABEL: "Domain has an empty label (two dots in a row or a leading dot).",
  HYPHEN_POSITION: "A label cannot start or end with a hyphen.",
  INVALID_PUNYCODE: "A label has invalid punycode or an invalid internationalized form.",
  IS_IP_ADDRESS: "This tool analyzes domain names, not IP addresses.",
  INVALID_TLD: "The top-level domain cannot be all digits.",
  SINGLE_LABEL: "Enter a full domain with a dot, such as example.com.",
  EMAIL_ADDRESS: "This looks like an email address. Enter a domain name instead.",
  EMPTY_BATCH: "Provide at least one domain.",
  TOO_MANY_DOMAINS: "Too many domains. The maximum is 100 per request.",
  PAYLOAD_TOO_LARGE: "Request body is too large.",
  DUPLICATE: "Duplicate of an earlier entry.",
};

export const NOTE_MESSAGES: Record<string, string> = {
  EXTRACTED_FROM_URL: "Analyzing the hostname extracted from the text you entered.",
  WILDCARD_STRIPPED: "Leading wildcard (*.) removed.",
  RESERVED_NAME: "Reserved or special-use name. The model verdict is not meaningful for it.",
  NORMALIZED: "Input was normalized (case, trailing dot or internationalized form).",
};

export const WARNING_MESSAGES: Record<string, string> = {
  UNDERSCORE: "Contains an underscore. Valid in DNS records, but not a valid hostname.",
  VERY_SHORT: "Very short name (under 4 characters). Little signal for analysis.",
  DIGIT_HEAVY: "Name is mostly digits.",
  LONG_LABEL: "Very long subdomain label. This pattern is also seen in DNS tunneling.",
  DEEP_SUBDOMAINS: "Deeply nested subdomains.",
  PRIVATE_SUFFIX: "Hosted under a private suffix (shared hosting platform).",
  HOMOGRAPH: "A label mixes scripts, which can imitate another name.",
};

export interface DomainInfo {
  original: string;
  ascii: string;
  display: string;
  notes: string[];
  /** Only warnings computable without the Public Suffix List. */
  warnings: string[];
}

export type DomainResult =
  | { ok: true; info: DomainInfo }
  | { ok: false; code: string; message: string };

const RESERVED = [
  "test", "example", "invalid", "localhost", "local", "onion", "internal",
  "home.arpa", "in-addr.arpa", "ip6.arpa", "example.com", "example.net", "example.org",
];
const LABEL_RE = /^[a-z0-9_-]+$/;
const NUMERIC_PART_RE = /^(?:0x[0-9a-f]+|[0-9]+)$/;
const SCRIPTS = ["Latin", "Cyrillic", "Greek", "Arabic", "Hebrew", "Han", "Hiragana", "Katakana", "Hangul", "Devanagari", "Thai"];
const SCRIPT_RES = SCRIPTS.map((s) => [s, new RegExp(`\\p{Script=${s}}`, "u")] as const);

const isAscii = (t: string) => [...t].every((c) => c.charCodeAt(0) < 128);

class DomainError extends Error {
  code: string;
  constructor(code: string) {
    super(MESSAGES[code]);
    this.code = code;
  }
}

/** RFC 3492 decode of the part after "xn--". Throws on malformed input. */
function punycodeDecode(input: string): string {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const out: number[] = [];
  const d = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(d, 0); j++) {
    if (input.charCodeAt(j) >= 0x80) throw new Error("bad");
    out.push(input.charCodeAt(j));
  }
  let n = 128, bias = 72, i = 0;
  const adapt = (delta: number, points: number, first: boolean) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / points);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  for (let idx = d > 0 ? d + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) throw new Error("bad");
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit >= base) throw new Error("bad");
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff) throw new Error("bad");
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

function extractHost(s: string): [string, boolean] {
  const orig = s;
  if (s.includes("://")) s = s.split("://").slice(1).join("://");
  for (const sep of "/?#") s = s.split(sep)[0];
  s = s.slice(s.lastIndexOf("@") + 1);
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end !== -1) s = s.slice(1, end);
  } else if (s.split(":").length === 2) {
    s = s.split(":")[0];
  }
  return [s, s !== orig];
}

function isIp(host: string): boolean {
  if (host.includes(":")) {
    return /^[0-9a-f:.]+$/.test(host) && host.split(":").length >= 3;
  }
  const parts = host.split(".");
  return parts.length <= 4 && parts.every((p) => NUMERIC_PART_RE.test(p));
}

function toAsciiLabel(label: string): string {
  if (isAscii(label)) return label;
  if (/[\p{Extended_Pictographic}\p{S}\p{P}]/u.test(label)) throw new DomainError("INVALID_CHARACTER");
  let host: string;
  try {
    host = new URL(`http://${label}`).hostname;
  } catch {
    throw new DomainError("INVALID_CHARACTER");
  }
  if (host.length > MAX_LABEL_LEN) throw new DomainError("LABEL_TOO_LONG");
  return host;
}

function script(ch: string): string | null {
  if (!/\p{L}/u.test(ch)) return null;
  for (const [name, re] of SCRIPT_RES) if (re.test(ch)) return name;
  return null;
}

export function normalizeAndValidate(raw: string): DomainResult {
  try {
    return { ok: true, info: run(raw) };
  } catch (e) {
    if (e instanceof DomainError) return { ok: false, code: e.code, message: e.message };
    throw e;
  }
}

function run(raw: string): DomainInfo {
  if (raw.length > MAX_RAW_LEN) throw new DomainError("TOO_LONG");
  const s = raw.trim();
  if (!s) throw new DomainError("EMPTY");
  if (/[\s\p{Cc}]/u.test(s)) throw new DomainError("INVALID_CHARACTER");

  const notes: string[] = [];
  if (s.includes("@") && !s.includes("://") && !/[/?#]/.test(s)) throw new DomainError("EMAIL_ADDRESS");
  let [host, changed] = extractHost(s);
  if (changed) notes.push("EXTRACTED_FROM_URL");
  if (!host) throw new DomainError("EMPTY");

  let normalized = host !== host.toLowerCase();
  host = host.toLowerCase();
  if (host.endsWith(".")) {
    host = host.slice(0, -1);
    normalized = true;
    if (!host) throw new DomainError("EMPTY");
  }
  if (host.startsWith("*.")) {
    host = host.slice(2);
    notes.push("WILDCARD_STRIPPED");
    if (!host) throw new DomainError("EMPTY");
  }
  if (isIp(host)) throw new DomainError("IS_IP_ADDRESS");

  if (!isAscii(host)) {
    host = host.normalize("NFC").replace(/[。．｡]/g, ".");
    normalized = true;
  }
  const labels = host.split(".").map(toAsciiLabel);
  const ascii = labels.join(".");

  if (ascii.length > MAX_DOMAIN_LEN) throw new DomainError("TOO_LONG");
  if (labels.some((l) => !l)) throw new DomainError("EMPTY_LABEL");
  if (labels.some((l) => l.length > MAX_LABEL_LEN)) throw new DomainError("LABEL_TOO_LONG");
  if (labels.some((l) => !LABEL_RE.test(l))) throw new DomainError("INVALID_CHARACTER");
  if (labels.some((l) => l.startsWith("-") || l.endsWith("-"))) throw new DomainError("HYPHEN_POSITION");

  const display = labels
    .map((l) => {
      if (l.slice(2, 4) !== "--") return l;
      if (!l.startsWith("xn--")) throw new DomainError("INVALID_PUNYCODE");
      try {
        const u = punycodeDecode(l.slice(4));
        if (!u) throw new Error("empty");
        return u;
      } catch {
        throw new DomainError("INVALID_PUNYCODE");
      }
    })
    .join(".");

  if (labels.length < 2) throw new DomainError("SINGLE_LABEL");
  if (/^[0-9]+$/.test(labels[labels.length - 1])) throw new DomainError("INVALID_TLD");

  if (normalized) notes.push("NORMALIZED");
  if (RESERVED.some((r) => ascii === r || ascii.endsWith("." + r))) notes.push("RESERVED_NAME");

  const warnings: string[] = [];
  if (labels.some((l) => l.includes("_"))) warnings.push("UNDERSCORE");
  if (display.split(".").some((l) => new Set([...l].map(script).filter(Boolean)).size > 1)) {
    warnings.push("HOMOGRAPH");
  }
  return { original: raw, ascii, display, notes, warnings };
}

/** Escaped, truncated copy of text for safe display in messages. */
export function safeInput(raw: string, limit = 100): string {
  return [...raw.slice(0, limit)]
    .map((c) => (/[\p{Cc}<>&"']/u.test(c) ? `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}` : c))
    .join("");
}

export type BatchStatus = "valid" | "normalized" | "invalid" | "duplicate";

export interface BatchLine {
  raw: string;
  status: BatchStatus;
  ascii?: string;
  display?: string;
  code?: string;
  message?: string;
  notes?: string[];
}

/** Split on newlines, commas and whitespace; validate each token; mark duplicates. */
export function parseBatch(text: string): BatchLine[] {
  const seen = new Set<string>();
  return text
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((raw): BatchLine => {
      const r = normalizeAndValidate(raw);
      if (!r.ok) return { raw, status: "invalid", code: r.code, message: r.message };
      if (seen.has(r.info.ascii)) {
        return { raw, status: "duplicate", ascii: r.info.ascii, code: "DUPLICATE", message: MESSAGES.DUPLICATE };
      }
      seen.add(r.info.ascii);
      return {
        raw,
        status: r.info.notes.length ? "normalized" : "valid",
        ascii: r.info.ascii,
        display: r.info.display,
        notes: r.info.notes,
      };
    });
}
