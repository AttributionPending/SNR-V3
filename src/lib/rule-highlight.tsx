/**
 * Lightweight syntax highlighter for detection rules (Sigma, YARA, Suricata).
 * Returns React elements with Tailwind color classes — no external dependencies.
 */
import React from 'react';

// ── Color classes ────────────────────────────────────────────────────────────
const C = {
  keyword:  'text-cyan-400',
  string:   'text-green-400',
  comment:  'text-slate-500 italic',
  number:   'text-orange-300',
  operator: 'text-purple-400',
  variable: 'text-yellow-300',
  action:   'text-red-400 font-semibold',
  tag:      'text-yellow-400',
  hex:      'text-orange-400',
  field:    'text-sky-300',
  default:  '', // inherit
};

type Token = { text: string; cls: string };

// ── Sigma (YAML-based) ──────────────────────────────────────────────────────

const SIGMA_TOP_KEYS = /^(title|id|status|description|author|date|modified|references|logsource|detection|fields|falsepositives|level|tags|related):/;
const SIGMA_NESTED_KEYS = /^\s+(category|product|service|definition|condition|selection\w*|filter\w*|keywords?\w*|timeframe):/;

function tokenizeSigmaLine(line: string): Token[] {
  // Comment
  if (/^\s*#/.test(line)) return [{ text: line, cls: C.comment }];

  // Top-level key
  const topMatch = line.match(SIGMA_TOP_KEYS);
  if (topMatch) {
    const colonIdx = line.indexOf(':');
    return [
      { text: line.slice(0, colonIdx + 1), cls: C.keyword },
      { text: line.slice(colonIdx + 1), cls: C.default },
    ];
  }

  // Nested key (selection, condition, etc.)
  const nestedMatch = line.match(SIGMA_NESTED_KEYS);
  if (nestedMatch) {
    const colonIdx = line.indexOf(':');
    const indent = line.match(/^(\s*)/)?.[1] ?? '';
    return [
      { text: indent, cls: C.default },
      { text: line.slice(indent.length, colonIdx + 1), cls: C.field },
      { text: line.slice(colonIdx + 1), cls: C.default },
    ];
  }

  // MITRE ATT&CK tags
  if (/^\s+-\s+attack\./.test(line)) {
    const dashIdx = line.indexOf('-');
    return [
      { text: line.slice(0, dashIdx + 1), cls: C.default },
      { text: line.slice(dashIdx + 1), cls: C.tag },
    ];
  }

  // Inline strings
  return tokenizeStringsAndOperators(line, 'sigma');
}

// ── YARA ─────────────────────────────────────────────────────────────────────

const YARA_KEYWORDS = /\b(rule|meta|strings|condition|import|include|private|global)\b/g;
const YARA_OPERATORS = /\b(and|or|not|any|all|of|them|at|in|for|true|false|contains|icontains|startswith|istartswith|endswith|iendswith|matches|wide|ascii|nocase|fullword|base64|xor|filesize|entrypoint|uint8|uint16|uint32|int8|int16|int32)\b/g;

function tokenizeYaraLine(line: string): Token[] {
  // Single-line comment
  if (/^\s*\/\//.test(line)) return [{ text: line, cls: C.comment }];

  const tokens: Token[] = [];
  // Split by interesting boundaries while preserving them
  const parts = line.split(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\/(?:[^/\\]|\\.)*\/|\{[^}]*\}|\$\w+)/g);

  for (const part of parts) {
    if (!part) continue;

    // Quoted string
    if (/^"/.test(part) || /^'/.test(part)) {
      tokens.push({ text: part, cls: C.string });
      continue;
    }

    // Regex
    if (/^\/.*\/$/.test(part)) {
      tokens.push({ text: part, cls: C.string });
      continue;
    }

    // Hex string { AB CD ?? }
    if (/^\{.*\}$/.test(part)) {
      tokens.push({ text: part, cls: C.hex });
      continue;
    }

    // Variable reference $name
    if (/^\$\w+/.test(part)) {
      tokens.push({ text: part, cls: C.variable });
      continue;
    }

    // Apply keyword + operator highlighting to remaining text
    let remaining = part;
    const subTokens: Token[] = [];
    let lastIdx = 0;

    // Combine keyword and operator patterns
    const combined = new RegExp(
      `(\\b(?:rule|meta|strings|condition|import|include|private|global)\\b)|(\\b(?:and|or|not|any|all|of|them|at|in|for|true|false|contains|icontains|startswith|istartswith|endswith|iendswith|matches|wide|ascii|nocase|fullword|base64|xor|filesize|entrypoint|uint8|uint16|uint32|int8|int16|int32)\\b)`,
      'g'
    );

    let m: RegExpExecArray | null;
    while ((m = combined.exec(remaining)) !== null) {
      if (m.index > lastIdx) {
        subTokens.push({ text: remaining.slice(lastIdx, m.index), cls: C.default });
      }
      subTokens.push({
        text: m[0],
        cls: m[1] ? C.keyword : C.operator,
      });
      lastIdx = m.index + m[0].length;
    }
    if (lastIdx < remaining.length) {
      subTokens.push({ text: remaining.slice(lastIdx), cls: C.default });
    }
    tokens.push(...subTokens);
  }

  return tokens;
}

// ── Suricata ─────────────────────────────────────────────────────────────────

const SURI_ACTIONS = /^(alert|drop|pass|reject|log|activate|dynamic)\b/;
const SURI_PROTOS = /\b(tcp|udp|icmp|ip|http|ftp|tls|ssl|smb|dns|dcerpc|smtp|imap|pop3|modbus|dnp3|enip|nfs|ssh|krb5|ikev2|tftp|ntp|dhcp|sip|rfb|mqtt|http2|pgsql|quic|pkthdr)\b/g;
const SURI_OPTION_KEYS = /\b(msg|content|nocase|depth|offset|distance|within|sid|rev|classtype|priority|metadata|reference|flow|flowbits|threshold|pcre|byte_test|byte_jump|byte_extract|fast_pattern|rawbytes|isdataat|dsize|flags|fragbits|ttl|tos|id|ipopts|ip_proto|geoip|fragoffset|window|ack|seq|itype|icode|icmp_id|icmp_seq|detection_filter|tag|target|filemd5|filesha1|filesha256|filesize|filemagic|filename|fileext|filestore|app-layer-protocol|ja3_hash|ja3s_hash|tls_cert_subject|tls_cert_issuer|tls_cert_serial|tls_sni|http_method|http_uri|http_raw_uri|http_header|http_raw_header|http_cookie|http_user_agent|http_host|http_content_type|http_stat_code|http_stat_msg|http_request_body|http_response_body|dns_query|dns_opcode|ssh_proto|ssh_software)\b/g;

function tokenizeSuricataLine(line: string): Token[] {
  // Comment
  if (/^\s*#/.test(line)) return [{ text: line, cls: C.comment }];

  const tokens: Token[] = [];

  // Check for action keyword at start
  const actionMatch = line.match(SURI_ACTIONS);
  if (actionMatch) {
    tokens.push({ text: actionMatch[0], cls: C.action });
    let rest = line.slice(actionMatch[0].length);

    // Find the options section (everything inside parentheses)
    const parenIdx = rest.indexOf('(');
    if (parenIdx !== -1) {
      const header = rest.slice(0, parenIdx + 1);
      const optionsPart = rest.slice(parenIdx + 1);

      // Highlight protocols and arrows in header
      tokens.push(...tokenizeSuriHeader(header));

      // Highlight options
      tokens.push(...tokenizeSuriOptions(optionsPart));
    } else {
      tokens.push(...tokenizeSuriHeader(rest));
    }
    return tokens;
  }

  // If line is continuation of options (inside parentheses)
  return tokenizeSuriOptions(line);
}

function tokenizeSuriHeader(header: string): Token[] {
  const tokens: Token[] = [];
  let remaining = header;
  let lastIdx = 0;

  // Highlight protocols
  const protoRe = new RegExp(SURI_PROTOS.source, 'g');
  let m: RegExpExecArray | null;

  // Direction arrows
  remaining = remaining.replace(/(->|<>)/g, (arrow) => `\x01ARROW${arrow}\x02`);

  const arrowParts = remaining.split(/(\x01ARROW.*?\x02)/g);
  for (const part of arrowParts) {
    const arrowMatch = part.match(/\x01ARROW(.*?)\x02/);
    if (arrowMatch) {
      tokens.push({ text: arrowMatch[1], cls: C.operator });
      continue;
    }

    // Highlight protocols in this part
    let pLastIdx = 0;
    protoRe.lastIndex = 0;
    while ((m = protoRe.exec(part)) !== null) {
      if (m.index > pLastIdx) tokens.push({ text: part.slice(pLastIdx, m.index), cls: C.default });
      tokens.push({ text: m[0], cls: C.tag });
      pLastIdx = m.index + m[0].length;
    }
    if (pLastIdx < part.length) tokens.push({ text: part.slice(pLastIdx), cls: C.default });
  }

  return tokens;
}

function tokenizeSuriOptions(text: string): Token[] {
  const tokens: Token[] = [];
  // Split by quoted strings to preserve them
  const parts = text.split(/("(?:[^"\\]|\\.)*")/g);

  for (const part of parts) {
    if (!part) continue;

    if (part.startsWith('"')) {
      tokens.push({ text: part, cls: C.string });
      continue;
    }

    // Highlight option keywords
    let lastIdx = 0;
    const optRe = new RegExp(SURI_OPTION_KEYS.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = optRe.exec(part)) !== null) {
      if (m.index > lastIdx) tokens.push({ text: part.slice(lastIdx, m.index), cls: C.default });
      tokens.push({ text: m[0], cls: C.field });
      lastIdx = m.index + m[0].length;
    }
    if (lastIdx < part.length) tokens.push({ text: part.slice(lastIdx), cls: C.default });
  }

  return tokens;
}

// ── Shared helpers ───────────────────────────────────────────────────────────

function tokenizeStringsAndOperators(line: string, dialect: string): Token[] {
  const tokens: Token[] = [];
  const parts = line.split(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g);

  for (const part of parts) {
    if (!part) continue;
    if (part.startsWith('"') || part.startsWith("'")) {
      tokens.push({ text: part, cls: C.string });
    } else if (dialect === 'sigma') {
      // Highlight sigma condition operators
      let remaining = part;
      let lastIdx = 0;
      const sigmaOps = /\b(and|or|not|1 of|all of|near)\b/g;
      let m: RegExpExecArray | null;
      while ((m = sigmaOps.exec(remaining)) !== null) {
        if (m.index > lastIdx) tokens.push({ text: remaining.slice(lastIdx, m.index), cls: C.default });
        tokens.push({ text: m[0], cls: C.operator });
        lastIdx = m.index + m[0].length;
      }
      if (lastIdx < remaining.length) tokens.push({ text: remaining.slice(lastIdx), cls: C.default });
    } else {
      tokens.push({ text: part, cls: C.default });
    }
  }
  return tokens;
}

// ── Public API ───────────────────────────────────────────────────────────────

export function highlightRule(
  content: string,
  ruleType: string,
): React.ReactNode {
  const type = ruleType.toLowerCase();
  const lines = content.split('\n');

  const tokenizer =
    type === 'sigma' ? tokenizeSigmaLine
    : type === 'yara' ? tokenizeYaraLine
    : type === 'suricata' ? tokenizeSuricataLine
    : null;

  if (!tokenizer) {
    // Unknown rule type — return plain text
    return content;
  }

  return lines.map((line, lineIdx) => {
    const tokens = tokenizer(line);
    return (
      <React.Fragment key={lineIdx}>
        {tokens.map((tok, tokIdx) =>
          tok.cls ? (
            <span key={tokIdx} className={tok.cls}>{tok.text}</span>
          ) : (
            <React.Fragment key={tokIdx}>{tok.text}</React.Fragment>
          )
        )}
        {lineIdx < lines.length - 1 ? '\n' : ''}
      </React.Fragment>
    );
  });
}
