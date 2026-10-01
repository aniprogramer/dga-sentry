/**
 * Utility functions for extracting and sanitizing domain names from
 * unstructured text, logs, and CSV files.
 */

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,}$/;

/**
 * Clean a candidate token by stripping protocol, path, port, query, and bounding characters.
 */
export function cleanDomainToken(rawToken: string): string | null {
  if (!rawToken) return null;

  let token = rawToken.trim();

  // Strip leading/trailing quotes, brackets, parens
  token = token.replace(/^[<"'\(\[\{]+|[>"'\)\]\},;]+$/g, "");

  // Strip protocol (http://, https://, etc.)
  token = token.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");

  // Strip userinfo (user:pass@)
  if (token.includes("@")) {
    const atParts = token.split("@");
    token = atParts[atParts.length - 1];
  }

  // Strip path, query params, hash
  token = token.split(/[/?#]/)[0];

  // Strip port (:8080, :443)
  token = token.split(":")[0];

  // Strip trailing dot
  token = token.replace(/\.+$/, "").trim().toLowerCase();

  if (!token || token.length > 253) return null;

  // Validate structure
  if (!DOMAIN_REGEX.test(token)) return null;

  // Check that labels are valid
  const labels = token.split(".");
  if (labels.length < 2) return null;

  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return null;
    if (label.startsWith("-") || label.endsWith("-")) return null;
  }

  // TLD cannot be purely numeric in DNS (RFC 1123, prevents IPv4 addresses and timestamps)
  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld)) return null;

  return token;
}

/**
 * Extract unique, valid domain names from raw text (e.g. pasted logs, multi-line lists).
 */
export function extractDomainsFromText(text: string): string[] {
  if (!text) return [];

  // Split on newlines, spaces, commas, semicolons, tabs, and pipes
  const tokens = text.split(/[\r\n,\t| ]+/);
  const seen = new Set<string>();
  const results: string[] = [];

  for (const rawToken of tokens) {
    const cleaned = cleanDomainToken(rawToken);
    if (cleaned && !seen.has(cleaned)) {
      seen.add(cleaned);
      results.push(cleaned);
    }
  }

  return results;
}

/**
 * Parse a simple CSV row respecting quoted values.
 */
function parseCsvRow(rowStr: string, delimiter: string = ","): string[] {
  const fields: string[] = [];
  let current = "";
  let insideQuotes = false;

  for (let i = 0; i < rowStr.length; i++) {
    const char = rowStr[i];
    if (char === '"') {
      if (insideQuotes && i + 1 < rowStr.length && rowStr[i + 1] === '"') {
        current += '"';
        i++; // skip escaped quote
      } else {
        insideQuotes = !insideQuotes;
      }
    } else if (char === delimiter && !insideQuotes) {
      fields.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  fields.push(current.trim());
  return fields;
}

/**
 * Detect column separator (comma, semicolon, or tab).
 */
function detectDelimiter(firstLine: string): string {
  const commaCount = (firstLine.match(/,/g) || []).length;
  const tabCount = (firstLine.match(/\t/g) || []).length;
  const semiCount = (firstLine.match(/;/g) || []).length;

  if (tabCount > commaCount && tabCount > semiCount) return "\t";
  if (semiCount > commaCount && semiCount > tabCount) return ";";
  return ",";
}

/**
 * Extract unique domains from CSV content by identifying domain column headers or scanning rows.
 */
export function extractDomainsFromCSV(csvContent: string): string[] {
  if (!csvContent) return [];

  const lines = csvContent
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length === 0) return [];

  const delimiter = detectDelimiter(lines[0]);
  const headerFields = parseCsvRow(lines[0], delimiter);

  // Look for a column matching domain-like headers
  const domainHeaderRegex = /^(?:domain|query|host|hostname|url|fqdn|destination_domain|dns_query|domain_name)$/i;
  let targetColIndex = -1;

  for (let i = 0; i < headerFields.length; i++) {
    const cleanHeader = headerFields[i].replace(/["']/g, "").trim();
    if (domainHeaderRegex.test(cleanHeader)) {
      targetColIndex = i;
      break;
    }
  }

  // Fallback: check if header field contains "domain", "query", "host"
  if (targetColIndex === -1) {
    for (let i = 0; i < headerFields.length; i++) {
      const cleanHeader = headerFields[i].replace(/["']/g, "").toLowerCase();
      if (
        cleanHeader.includes("domain") ||
        cleanHeader.includes("hostname") ||
        cleanHeader.includes("query")
      ) {
        targetColIndex = i;
        break;
      }
    }
  }

  const seen = new Set<string>();
  const results: string[] = [];

  if (targetColIndex !== -1) {
    // Process rows 1..N using target column
    for (let i = 1; i < lines.length; i++) {
      const row = parseCsvRow(lines[i], delimiter);
      if (row.length > targetColIndex) {
        const cleaned = cleanDomainToken(row[targetColIndex]);
        if (cleaned && !seen.has(cleaned)) {
          seen.add(cleaned);
          results.push(cleaned);
        }
      }
    }
  }

  // If no matching column was found or no domains were extracted, fallback to scanning full text
  if (results.length === 0) {
    return extractDomainsFromText(csvContent);
  }

  return results;
}
