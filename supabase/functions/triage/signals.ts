// Code-computed facts about the input. These run before Claude and can't be
// talked out of anything: the verifier and score floors rely on them.

import { editDistance, norm, stripTags, ZERO_WIDTH } from "./text.ts";
import type { Tool } from "./contract.ts";

export interface HiddenText { text: string; method: string }
export interface AiPhrase { text: string; strength: "strong" | "soft"; hidden: boolean }
export interface UrlInfo {
  url: string;
  domain: string;
  ip: boolean;
  shortener: boolean;
  defanged: boolean;
  lookalike: string | null; // brand it imitates
}

export interface Signals {
  headers_present: boolean;
  visible_text: string;
  hidden_text: HiddenText[];
  zero_width_chars: number;
  urls: UrlInfo[];
  link_mismatch: { shown: string; actual: string }[];
  lookalike_domains: string[];
  keyword_hits: string[];
  money_request: boolean;
  credential_request: boolean;
  risky_attachments: string[];
  auth_fail: boolean;
  ai_phrases: AiPhrase[];
  tag_like_text: boolean;
  alert_fields: Record<string, string>; // flattened alert JSON (alerts only)
  encoded_powershell: boolean;
  office_spawned_script: boolean;
  mass_rename: boolean;
}

// Initial list from the team guide + kickoff notes. Replace with keywords.json (spec §9) when built.
export const KEYWORDS = [
  "urgent", "immediately", "suspended", "verify", "24 hours", "act now", "winner",
  "click here", "quick and easy money", "i need help", "final notice", "claim now",
  "gift card", "password", "dear valued customer", "confirm your", "account locked",
  "wire transfer", "limited time", "congratulations",
];

const BRANDS = [
  "microsoft", "office365", "outlook", "paypal", "docusign", "okta", "google", "apple",
  "amazon", "dropbox", "adobe", "zoom", "slack", "wellsfargo", "chase", "bankofamerica",
  "fedex", "ups", "dhl", "linkedin",
];

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
]);

// Tier 1: instruction-shaped text. Floors the score with no LLM needed.
const STRONG_AI = [
  /ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions|rules|prompts?)/gi,
  /disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|prompts?)/gi,
  /(?:classify|mark|label|treat|flag)\s+(?:this|it|the)\s*(?:email|message|alert|ticket)?\s+as\s+(?:safe|benign|legitimate|clean|not\s+(?:spam|phishing))/gi,
  /this\s+(?:email|message)\s+(?:has\s+been|was|is)\s+(?:verified|approved|whitelisted|cleared)\s+by/gi,
  /you\s+are\s+now\s+(?:an?\s+)?[\w-]+/gi,
  /new\s+instructions\s*:/gi,
];

// Tier 2: mentions of AI/automation. Only a signal unless hidden or the LLM agrees.
const SOFT_AI = [
  /\b(?:ai|ml)\s+(?:assistant|model|agent|system|filter)s?\b/gi,
  /\blanguage\s+model\b/gi,
  /\bautomated\s+(?:system|scanner|filter|review)\b/gi,
  /\bsystem\s+prompt\b/gi,
  /\bspam\s+filter\b/gi,
];

const HIDDEN_STYLE =
  /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.\d+)?(?:px|pt|em|rem)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|color\s*:\s*(?:#fff(?:fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255))/i;

const MONEY =
  /gift\s*cards?|wire\s+(?:transfer|the\s+funds)|bank(?:ing)?\s+(?:details|account|information)\s+(?:have\s+|has\s+)?(?:changed|been\s+updated|updated)|(?:pay|send\s+payment|remit)\b[^.\n]{0,40}\b(?:today|immediately|now)|bitcoin|crypto(?:currency)?\s+wallet/i;

const CREDENTIAL =
  /verify\s+(?:your\s+)?(?:account|identity|password|login)|confirm\s+(?:your\s+)?(?:password|credentials|login|account)|(?:log\s*in|sign\s*in)\s+(?:below|here|now|to\s+(?:verify|confirm|restore|keep))|reset\s+your\s+password|account\s+(?:will\s+be\s+|has\s+been\s+)?(?:suspended|locked|disabled|deactivated)/i;

const RISKY_FILE = /\b[\w\-]+(?:\.[\w\-]+)*\.(?:html?|iso|img|js|vbs|hta|scr|exe|docm|xlsm|pptm|lnk)\b/gi;

function domainOf(url: string): string {
  const clean = url.replace(/\[\.\]/g, ".").replace(/^hxxp/i, "http").replace(/^www\./i, "http://www.");
  try {
    return new URL(clean).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return clean.replace(/^[a-z]+:\/\//i, "").split(/[/?#:]/)[0].toLowerCase().replace(/^www\./, "");
  }
}

// Map look-alike characters to one form so "paypa1" and "paypal" compare equal.
function unconfuse(s: string): string {
  return s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/[1i|]/g, "l")
    .replace(/3/g, "e").replace(/5/g, "s").replace(/4/g, "a");
}

// Returns the brand a domain imitates, or null.
export function lookalikeBrand(domain: string): string | null {
  const labels = domain.split(".");
  for (const brand of BRANDS) {
    // Official: the brand is the registrable label (brand.com, login.brand.com, brand.co.uk).
    const reg = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
    const regAlt = labels.length >= 3 ? labels[labels.length - 3] : "";
    if (reg === brand || (regAlt === brand && /^(co|com|org|net)$/.test(reg))) continue;
    for (const token of domain.split(/[.\-_]/)) {
      if (token === brand) return brand; // brand used inside an unrelated domain
      if (unconfuse(token) === unconfuse(brand)) return brand; // paypa1, rnicrosoft, micros0ft
      // One typo only for long brands; short ones collide with real words (apple/apply).
      if (brand.length >= 7 && editDistance(token, brand) === 1) return brand;
    }
  }
  return null;
}

function extractUrls(text: string): UrlInfo[] {
  const found = new Set<string>();
  for (const m of text.matchAll(/\b(?:h(?:tt|xx)ps?:\/\/|www\.)[^\s"'<>)\]]+(?:\[\.\][^\s"'<>)\]]+)*/gi)) found.add(m[0]);
  for (const m of text.matchAll(/\b[\w-]+(?:\[\.\][\w-]+)+(?:\/[^\s"'<>)]*)?/g)) found.add(m[0]);
  return [...found].map((url) => {
    const domain = domainOf(url);
    return {
      url,
      domain,
      ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(domain),
      shortener: SHORTENERS.has(domain),
      defanged: /\[\.\]|^hxxp/i.test(url),
      lookalike: lookalikeBrand(domain),
    };
  });
}

function scanAiPhrases(text: string, hidden: boolean): AiPhrase[] {
  const out: AiPhrase[] = [];
  for (const re of STRONG_AI) for (const m of text.matchAll(re)) out.push({ text: m[0], strength: "strong", hidden });
  for (const re of SOFT_AI) for (const m of text.matchAll(re)) out.push({ text: m[0], strength: "soft", hidden });
  return out;
}

// Splits HTML into visible text and hidden text (white/zero-size/display:none/comments).
function splitHtml(html: string): { visible: string; hidden: HiddenText[]; links: { shown: string; href: string }[] } {
  const hidden: HiddenText[] = [];
  const links: { shown: string; href: string }[] = [];
  let rest = html.replace(/<!--([\s\S]*?)-->/g, (_, c: string) => {
    if (c.trim()) hidden.push({ text: c.trim(), method: "html-comment" });
    return " ";
  });
  // Repeat so nested hidden elements are caught from the inside out.
  for (let i = 0; i < 3; i++) {
    rest = rest.replace(
      /<(\w+)\b([^>]*?)style\s*=\s*(["'])([^"']*)\3([^>]*)>([\s\S]*?)<\/\1>/gi,
      (whole, _tag, _a, _q, style: string, _b, inner: string) => {
        const m = style.match(HIDDEN_STYLE);
        if (!m) return whole;
        const text = stripTags(inner);
        if (text) hidden.push({ text, method: m[1].split(/\s*:/)[0].toLowerCase() });
        return " ";
      },
    );
  }
  for (const m of rest.matchAll(/<a\b[^>]*href\s*=\s*(["'])([^"']+)\1[^>]*>([\s\S]*?)<\/a>/gi)) {
    links.push({ href: m[2], shown: stripTags(m[3]) });
  }
  // Keep hrefs visible to the URL scanner by appending them.
  const visible = stripTags(rest);
  return { visible, hidden, links };
}

function flattenJson(value: unknown, prefix = "", out: Record<string, string> = {}): Record<string, string> {
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      flattenJson(v, prefix ? `${prefix}.${k}` : k, out);
    }
  } else if (value !== undefined) {
    out[prefix || "value"] = String(value);
  }
  return out;
}

export function computeSignals(tool: Tool, input: string): Signals {
  const raw = input ?? "";
  const zero_width_chars = (raw.match(ZERO_WIDTH) ?? []).length;
  const noZw = raw.replace(ZERO_WIDTH, "");

  let visible = noZw;
  let hidden: HiddenText[] = [];
  let links: { shown: string; href: string }[] = [];
  if (/<(html|body|div|p|span|a|table|font)\b/i.test(noZw)) {
    ({ visible, hidden, links } = splitHtml(noZw));
  }

  let alert_fields: Record<string, string> = {};
  if (tool === "alert") {
    try {
      alert_fields = flattenJson(JSON.parse(noZw));
    } catch { /* plain-text alert */ }
  }

  const hrefText = links.map((l) => l.href).join("\n");
  const urls = extractUrls(`${visible}\n${hrefText}`);
  const link_mismatch = links
    .map((l) => ({ shown: l.shown, actual: l.href, shownDomain: extractUrls(l.shown)[0]?.domain }))
    .filter((l) => l.shownDomain && l.shownDomain !== domainOf(l.actual))
    .map(({ shown, actual }) => ({ shown, actual }));

  const n = norm(visible);
  const withoutUrls = visible.replace(/\b(?:h(?:tt|xx)ps?:\/\/|www\.)\S+/gi, " ");
  const risky_attachments = [...new Set((withoutUrls.match(RISKY_FILE) ?? []).map((f) => f.toLowerCase()))];
  if (/password[- ]protected\s+(?:zip|archive|file)/i.test(visible)) risky_attachments.push("password-protected archive");

  const ai_phrases = [
    ...scanAiPhrases(visible, false),
    ...hidden.flatMap((h) => scanAiPhrases(h.text, true)),
  ];

  const headers_present = /^(from|received|return-path|authentication-results|reply-to):/im.test(noZw);

  return {
    headers_present,
    visible_text: visible,
    hidden_text: hidden,
    zero_width_chars,
    urls,
    link_mismatch,
    lookalike_domains: [...new Set(urls.filter((u) => u.lookalike).map((u) => u.domain))],
    keyword_hits: KEYWORDS.filter((k) => n.includes(k)),
    money_request: MONEY.test(visible),
    credential_request: CREDENTIAL.test(visible),
    risky_attachments,
    auth_fail: headers_present && /\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|none)\b/i.test(noZw),
    ai_phrases,
    tag_like_text: /<\s*\/?\s*(?:untrusted|hidden_content|signals|profile|system)\w*/i.test(noZw),
    alert_fields,
    encoded_powershell: /powershell[^\n"]*\s-(?:e|en|enc|encodedcommand)\b/i.test(noZw),
    office_spawned_script:
      /(winword|excel|powerpnt|outlook)\.exe[\s\S]{0,80}?(powershell|cmd|wscript|cscript|mshta|rundll32)\.exe/i.test(noZw),
    mass_rename: /\.locked\b|renamed?\s+\d{2,}|hundreds\s+of\s+files/i.test(noZw),
  };
}

// Defanged links are not suspicious by themselves: our own demo samples defang every link.
export function isSuspiciousUrl(u: UrlInfo): boolean {
  return u.ip || u.shortener || u.lookalike !== null;
}
