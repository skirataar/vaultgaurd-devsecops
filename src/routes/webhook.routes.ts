import { Router, Request, Response } from 'express';
import { safeOutboundFetch } from '../security/ssrfGuard';

export const webhookRouter = Router();

/**
 * Endpoint: POST /api/webhooks/verify
 * Demonstrates OWASP A10:2021 / CWE-918: Server-Side Request Forgery (SSRF)
 *
 * Body: { "targetUrl": "https://merchant.example.com/webhook" }
 *
 * Vulnerable mode: Directly dispatches `fetch(targetUrl)` without validating host or resolved IP.
 * Secure mode: Enforces strict SSRF guard (HTTPS only, DNS resolution inspection, blocks loopback/private/metadata ranges).
 */
webhookRouter.post('/verify', async (req: Request, res: Response) => {
  const { targetUrl } = req.body || {};
  const isVulnerable = req.securityMode === 'vulnerable';

  if (!targetUrl || typeof targetUrl !== 'string') {
    res.status(400).json({
      error: 'Missing required field: targetUrl must be a valid string',
      code: 'INVALID_INPUT',
    });
    return;
  }

  try {
    if (isVulnerable) {
      // VULNERABLE PATTERN (CWE-918 SSRF):
      // The server takes an unvalidated user-supplied URL and makes an arbitrary outbound network request.
      // An attacker can supply:
      // - 'http://169.254.169.254/latest/meta-data/' to steal cloud IAM credentials
      // - 'http://127.0.0.1:4000/api/...' to access internal loopback services
      // - 'http://10.0.0.1/' to pivot into internal corporate networks
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);

        const response = await fetch(targetUrl, {
          method: 'GET',
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const text = await response.text();

        res.status(200).json({
          status: 'success',
          securityMode: 'vulnerable',
          targetUrl,
          remoteStatus: response.status,
          snippet: text.slice(0, 300),
          _securityTelemetry: {
            vulnerability: 'CWE-918: Unrestricted outbound fetch permitted',
            hostValidated: false,
            dnsChecked: false,
            privateRangesBlocked: false,
          },
        });
        return;
      } catch (fetchErr: any) {
        res.status(502).json({
          error: 'Outbound network request failed in vulnerable mode',
          targetUrl,
          details: fetchErr.message,
          securityMode: 'vulnerable',
        });
        return;
      }
    }

    // SECURE PATTERN:
    // 1. Enforces HTTPS scheme only
    // 2. Performs comprehensive DNS resolution across all A and AAAA records
    // 3. Blocks Loopback (127.0.0.0/8, ::1), RFC 1918 Private Ranges, and Link-Local/Cloud Metadata (169.254.0.0/16)
    // 4. Disables automatic redirect following ('manual') to prevent redirect-based SSRF bypass
    const result = await safeOutboundFetch(targetUrl);

    res.status(200).json({
      status: 'success',
      securityMode: 'secure',
      targetUrl,
      remoteStatus: result.status,
      snippet: result.snippet,
      resolvedIps: result.resolvedIps,
      _securityTelemetry: {
        vulnerabilityNeutralized: true,
        ssrfGuardEnforced: true,
        protocol: 'https',
      },
    });
  } catch (err: any) {
    res.status(400).json({
      error: `SSRF Guard Rejection: ${err.message}`,
      code: err.code || 'SSRF_BLOCKED',
      targetUrl,
      resolvedIps: err.resolvedIps,
    });
  }
});
