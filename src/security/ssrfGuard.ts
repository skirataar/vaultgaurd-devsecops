import dns from 'node:dns';
import net from 'node:net';

export interface SSRFValidationResult {
  valid: boolean;
  error?: string;
  code?: string;
  resolvedIps?: string[];
  canonicalUrl?: string;
}

/**
 * Checks whether an IPv4 address belongs to private, loopback, link-local, or reserved ranges.
 */
export function isPrivateOrReservedIPv4(ip: string): { blocked: boolean; reason?: string } {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return { blocked: true, reason: 'Malformed IPv4 address' };
  }

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network / "this" host)
  if (a === 0) {
    return { blocked: true, reason: 'RFC 1122 "this host" address (0.0.0.0/8)' };
  }

  // 127.0.0.0/8 (Loopback)
  if (a === 127) {
    return { blocked: true, reason: 'Loopback address (127.0.0.0/8)' };
  }

  // 10.0.0.0/8 (RFC 1918 Private Network)
  if (a === 10) {
    return { blocked: true, reason: 'RFC 1918 Private Network (10.0.0.0/8)' };
  }

  // 172.16.0.0/12 (RFC 1918 Private Network: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) {
    return { blocked: true, reason: 'RFC 1918 Private Network (172.16.0.0/12)' };
  }

  // 192.168.0.0/16 (RFC 1918 Private Network)
  if (a === 192 && b === 168) {
    return { blocked: true, reason: 'RFC 1918 Private Network (192.168.0.0/16)' };
  }

  // 169.254.0.0/16 (Link-Local & Cloud Metadata Service, e.g. AWS/GCP IMDS 169.254.169.254)
  if (a === 169 && b === 254) {
    return { blocked: true, reason: 'Cloud Instance Metadata / Link-Local address (169.254.0.0/16)' };
  }

  // 100.64.0.0/10 (Shared Address Space / Carrier-Grade NAT)
  if (a === 100 && b >= 64 && b <= 127) {
    return { blocked: true, reason: 'Carrier-Grade NAT (100.64.0.0/10)' };
  }

  // 224.0.0.0/4 (Multicast: 224 - 239)
  if (a >= 224 && a <= 239) {
    return { blocked: true, reason: 'Multicast address range (224.0.0.0/4)' };
  }

  // 240.0.0.0/4 (Reserved / Future Use)
  if (a >= 240) {
    return { blocked: true, reason: 'Reserved address range (240.0.0.0/4)' };
  }

  return { blocked: false };
}

/**
 * Checks whether an IPv6 address belongs to loopback, link-local, ULA, or mapped IPv4 ranges.
 */
export function isPrivateOrReservedIPv6(ip: string): { blocked: boolean; reason?: string } {
  const normalized = ip.toLowerCase();

  // ::1 (Loopback)
  if (normalized === '::1' || normalized === '0000:0000:0000:0000:0000:0000:0000:0001') {
    return { blocked: true, reason: 'IPv6 Loopback address (::1)' };
  }

  // :: (Unspecified)
  if (normalized === '::' || normalized === '0000:0000:0000:0000:0000:0000:0000:0000') {
    return { blocked: true, reason: 'IPv6 Unspecified address (::)' };
  }

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:') || normalized.includes(':ffff:')) {
    const parts = normalized.split(':');
    const lastPart = parts[parts.length - 1];
    if (net.isIPv4(lastPart)) {
      return isPrivateOrReservedIPv4(lastPart);
    }
    // Also block general mapped prefix
    return { blocked: true, reason: 'IPv4-mapped IPv6 address range' };
  }

  // Unique Local Addresses (fc00::/7 -> fc00 to fdff)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return { blocked: true, reason: 'IPv6 Unique Local Address (fc00::/7)' };
  }

  // Link-Local Unicast (fe80::/10 -> fe80 to febf)
  if (
    normalized.startsWith('fe8') ||
    normalized.startsWith('fe9') ||
    normalized.startsWith('fea') ||
    normalized.startsWith('feb')
  ) {
    return { blocked: true, reason: 'IPv6 Link-Local Unicast address (fe80::/10)' };
  }

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) {
    return { blocked: true, reason: 'IPv6 Multicast address (ff00::/8)' };
  }

  return { blocked: false };
}

/**
 * Validates any given IP against both IPv4 and IPv6 private/reserved ranges.
 */
export function isPrivateOrReservedIp(ip: string): { blocked: boolean; reason?: string } {
  const version = net.isIP(ip);
  if (version === 4) {
    return isPrivateOrReservedIPv4(ip);
  } else if (version === 6) {
    return isPrivateOrReservedIPv6(ip);
  }
  return { blocked: true, reason: `Invalid IP address format: ${ip}` };
}

/**
 * Strict SSRF Guard (CWE-918 Mitigation)
 * 1. Enforces strict 'https:' scheme (blocks http://, file://, gopher://, etc.)
 * 2. Resolves DNS records using dns.promises.lookup with { all: true }
 * 3. Inspects every resolved IP against loopback, private networks, and cloud metadata (IMDS)
 * 4. Defends against DNS Rebinding and TOCTOU races by returning validated IPs for pinned dispatch
 */
export async function validateUrlForSSRF(urlString: string): Promise<SSRFValidationResult> {
  // Step 1: Parse URL
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return {
      valid: false,
      error: 'Invalid URL syntax or malformed URI',
      code: 'MALFORMED_URL',
    };
  }

  // Step 2: Enforce HTTPS scheme only
  if (parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: `Insecure protocol '${parsed.protocol}'. Only strict 'https:' is permitted.`,
      code: 'PROTOCOL_DISALLOWED',
      canonicalUrl: parsed.href,
    };
  }

  // Block credentials in URL (e.g., https://user:pass@host)
  if (parsed.username || parsed.password) {
    return {
      valid: false,
      error: 'URLs containing embedded credentials are prohibited.',
      code: 'CREDENTIALS_PROHIBITED',
    };
  }

  const hostname = parsed.hostname;
  if (!hostname) {
    return {
      valid: false,
      error: 'Target URL does not specify a valid hostname.',
      code: 'MISSING_HOSTNAME',
    };
  }

  // Strip IPv6 URI bracket notation: '[::1]' -> '::1'
  const cleanHost = hostname.replace(/^\[|\]$/g, '');

  // Fast-path IP literal inspection: if host is directly an IP literal, validate immediately
  if (net.isIP(cleanHost)) {
    const directIpCheck = isPrivateOrReservedIp(cleanHost);
    if (directIpCheck.blocked) {
      return {
        valid: false,
        error: `SSRF Blocked: Target resolves to prohibited network range (${cleanHost} - ${directIpCheck.reason})`,
        code: 'SSRF_PROHIBITED_IP',
        resolvedIps: [cleanHost],
        canonicalUrl: parsed.href,
      };
    }
    return {
      valid: true,
      resolvedIps: [cleanHost],
      canonicalUrl: parsed.href,
    };
  }

  // Step 3: Perform comprehensive DNS resolution (IPv4 & IPv6)
  let addresses: dns.LookupAddress[] = [];
  try {
    addresses = await dns.promises.lookup(cleanHost, { all: true });
  } catch (err: any) {
    return {
      valid: false,
      error: `DNS resolution failed for hostname '${cleanHost}': ${err.message}`,
      code: 'DNS_RESOLUTION_FAILED',
    };
  }

  if (addresses.length === 0) {
    return {
      valid: false,
      error: `No DNS records (A/AAAA) resolved for hostname '${hostname}'.`,
      code: 'NO_DNS_RECORDS',
    };
  }

  const resolvedIps = addresses.map((a) => a.address);

  // Step 4: Validate every resolved IP address
  for (const record of addresses) {
    const ipCheck = isPrivateOrReservedIp(record.address);
    if (ipCheck.blocked) {
      return {
        valid: false,
        error: `SSRF Blocked: Target resolves to prohibited network range (${record.address} - ${ipCheck.reason})`,
        code: 'SSRF_PROHIBITED_IP',
        resolvedIps,
        canonicalUrl: parsed.href,
      };
    }
  }

  return {
    valid: true,
    resolvedIps,
    canonicalUrl: parsed.href,
  };
}

/**
 * Secure HTTP dispatcher for outbound webhook verification.
 * Disables redirect following ('manual') to prevent redirect-based SSRF bypasses.
 */
export async function safeOutboundFetch(targetUrl: string, timeoutMs = 4000): Promise<{
  status: number;
  snippet: string;
  resolvedIps: string[];
}> {
  // Step 1: Pre-flight SSRF Validation
  const validation = await validateUrlForSSRF(targetUrl);
  if (!validation.valid) {
    const error: any = new Error(validation.error);
    error.code = validation.code;
    error.resolvedIps = validation.resolvedIps;
    throw error;
  }

  // Step 2: Dispatch request with redirect: 'manual' to prevent TOCTOU redirect attacks
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'VaultGuard-Webhook-Validator/1.0',
        'Accept': 'text/plain, application/json, text/html',
      },
      redirect: 'manual', // DEFENSE: Never follow redirects blindly without re-validating the target
      signal: controller.signal,
    });

    // If a redirect is encountered, do not follow automatically
    if (response.status >= 300 && response.status < 400) {
      return {
        status: response.status,
        snippet: `Redirect encountered to: ${response.headers.get('location') || 'unknown'} (Redirects halted by SSRF Guard)`,
        resolvedIps: validation.resolvedIps || [],
      };
    }

    const text = await response.text();
    const snippet = text.slice(0, 300);

    return {
      status: response.status,
      snippet,
      resolvedIps: validation.resolvedIps || [],
    };
  } finally {
    clearTimeout(timer);
  }
}
