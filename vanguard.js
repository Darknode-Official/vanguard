// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// VANGUARD — Autonomous Attack Surface Intelligence Engine
// The most comprehensive browser-based penetration testing reconnaissance tool.
// For AUTHORIZED SECURITY TESTING ONLY. Always obtain explicit written permission
// before scanning any target. Unauthorized scanning is illegal under the CFAA and
// equivalent international legislation.

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

// ============================================================================
// VANGUARD ENGINE STATE
// ============================================================================
var _vgState = {
  target: null,
  running: false,
  aborted: false,
  phase: 0,
  totalPhases: 10,
  results: {
    dns: null,
    subdomains: null,
    hosts: null,
    tech: null,
    security: null,
    vulns: null,
    infra: null,
    email: null,
    score: null,
    report: null
  },
  log: [],
  startTime: null,
  findings: [],
  phaseStatus: [] // 'pending','running','complete','error' for each phase
};

var _vgPhaseNames = [
  'TARGET ACQUISITION',
  'SUBDOMAIN DISCOVERY',
  'HOST PROBING',
  'TECHNOLOGY FINGERPRINTING',
  'SECURITY ASSESSMENT',
  'VULNERABILITY CORRELATION',
  'INFRASTRUCTURE ANALYSIS',
  'EMAIL SECURITY',
  'ATTACK SURFACE SCORING',
  'REPORT GENERATION'
];

// ============================================================================
// SUBDOMAIN WORDLIST
// ============================================================================
var _vgSubdomainWordlist = [
  'www','mail','ftp','admin','api','dev','staging','test','beta','vpn','remote',
  'portal','app','cdn','media','static','blog','shop','store','support','help',
  'docs','wiki','git','ci','jenkins','grafana','prometheus','kibana','elastic',
  'redis','mongo','mysql','postgres','db','database','backup','old','new','legacy',
  'archive','assets','files','upload','download','img','images','video','auth',
  'login','sso','id','oauth','accounts','billing','pay','checkout','cart','order',
  'crm','erp','hr','internal','intranet','extranet','corp','office','teams','meet',
  'chat','slack','jira','confluence','bitbucket','gitlab','github','aws','cloud',
  'gcp','azure','s3','storage','lambda','functions','graphql','ws','socket',
  'stream','feed','rss','xml','json','status','health','monitor','metrics',
  'analytics','tracking','ads','marketing','campaign','newsletter','mx','smtp',
  'pop','imap','webmail','autodiscover','exchange','owa','ns1','ns2','dns1','dns2',
  'vpn1','vpn2','gw','gateway','proxy','cache','waf','edge','lb','loadbalancer',
  'node1','node2','worker','queue','cron','scheduler','sandbox','demo','preview',
  'uat','qa','release','canary','prod','production','panel','dashboard','console',
  'manage','mgmt','infra','k8s','kubernetes','docker','registry','vault',
  'secrets','config','telemetry','logs','trace','sentry','datadog','newrelic',
  'web','www2','www3','m','mobile','go','link','links','redirect','proxy1',
  'proxy2','relay','smtp2','ns3','ns4'
];

// ============================================================================
// TECHNOLOGY FINGERPRINT SIGNATURES
// ============================================================================
var _vgTechSignatures = [
  { name: 'Nginx', category: 'Server', detect: function(h) { return /nginx/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Apache', category: 'Server', detect: function(h) { return /apache/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Microsoft IIS', category: 'Server', detect: function(h) { return /microsoft-iis/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'LiteSpeed', category: 'Server', detect: function(h) { return /litespeed/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Caddy', category: 'Server', detect: function(h) { return /caddy/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Cloudflare', category: 'CDN/WAF', detect: function(h) { return h.has('cf-ray') || /cloudflare/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'AWS CloudFront', category: 'CDN', detect: function(h) { return h.has('x-amz-cf-id') || h.has('x-amz-cf-pop'); }, severity: 'info' },
  { name: 'Akamai', category: 'CDN', detect: function(h) { return h.has('x-akamai-transformed') || /AkamaiGHost/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Fastly', category: 'CDN', detect: function(h) { return h.has('x-served-by') && h.has('x-cache') && h.has('x-timer'); }, severity: 'info' },
  { name: 'Varnish Cache', category: 'Cache', detect: function(h) { return h.has('x-varnish') || /varnish/i.test(h.get('via') || ''); }, severity: 'info' },
  { name: 'PHP', category: 'Language', detect: function(h) { return /php/i.test(h.get('x-powered-by') || ''); }, severity: 'low' },
  { name: 'ASP.NET', category: 'Framework', detect: function(h) { return /asp\.net/i.test(h.get('x-powered-by') || '') || h.has('x-aspnet-version'); }, severity: 'low' },
  { name: 'Express.js', category: 'Framework', detect: function(h) { return /express/i.test(h.get('x-powered-by') || ''); }, severity: 'info' },
  { name: 'Next.js', category: 'Framework', detect: function(h) { return h.has('x-nextjs-cache') || h.has('x-nextjs-matched-path'); }, severity: 'info' },
  { name: 'WordPress', category: 'CMS', detect: function(h) { return /wp-json/i.test(h.get('link') || ''); }, severity: 'low' },
  { name: 'Shopify', category: 'CMS', detect: function(h) { return h.has('x-shopid') || h.has('x-shopify-stage'); }, severity: 'info' },
  { name: 'Firebase', category: 'Platform', detect: function(h) { return /Google Frontend/i.test(h.get('server') || '') || h.has('x-cloud-trace-context'); }, severity: 'info' },
  { name: 'Vercel', category: 'Platform', detect: function(h) { return h.has('x-vercel-id') || /vercel/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Netlify', category: 'Platform', detect: function(h) { return h.has('x-nf-request-id'); }, severity: 'info' },
  { name: 'Heroku', category: 'Platform', detect: function(h) { return h.has('via') && /vegur/i.test(h.get('via') || ''); }, severity: 'info' },
  { name: 'AWS S3', category: 'Storage', detect: function(h) { return /AmazonS3/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Google Cloud', category: 'Platform', detect: function(h) { return h.has('x-cloud-trace-context') || /GSE/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Imperva/Incapsula WAF', category: 'WAF', detect: function(h) { return h.has('x-iinfo') || /incap/i.test(h.get('x-cdn') || ''); }, severity: 'info' },
  { name: 'AWS WAF', category: 'WAF', detect: function(h) { return h.has('x-amzn-waf-action'); }, severity: 'info' },
  { name: 'Sucuri WAF', category: 'WAF', detect: function(h) { return h.has('x-sucuri-id') || /Sucuri/i.test(h.get('server') || ''); }, severity: 'info' },
  { name: 'Ruby on Rails', category: 'Framework', detect: function(h) { return /Phusion Passenger/i.test(h.get('server') || '') || h.has('x-request-id') && h.has('x-runtime'); }, severity: 'info' },
  { name: 'Django', category: 'Framework', detect: function(h) { return h.has('x-frame-options') && (h.get('x-frame-options') || '').toUpperCase() === 'DENY' && /text\/html/i.test(h.get('content-type') || ''); }, severity: 'info' },
  { name: 'Laravel', category: 'Framework', detect: function(h) { return /laravel/i.test(h.get('set-cookie') || ''); }, severity: 'low' }
];

// ============================================================================
// SECURITY HEADERS TO CHECK
// ============================================================================
var _vgSecurityHeaders = [
  { header: 'strict-transport-security', name: 'HSTS', weight: 15, check: function(v) { if (!v) return { grade: 'F', note: 'Missing — no HTTPS enforcement' }; if (/max-age=\d{8,}/.test(v) && /includeSubDomains/i.test(v)) return { grade: 'A', note: 'Strong — long max-age with includeSubDomains' }; if (/max-age=\d{5,}/.test(v)) return { grade: 'B', note: 'Present but could be stronger' }; return { grade: 'C', note: 'Weak max-age value' }; } },
  { header: 'content-security-policy', name: 'CSP', weight: 20, check: function(v) { if (!v) return { grade: 'F', note: 'Missing — XSS protection gap' }; if (/unsafe-inline|unsafe-eval/i.test(v)) return { grade: 'C', note: 'Present but allows unsafe-inline/eval' }; if (/default-src/i.test(v)) return { grade: 'A', note: 'Comprehensive policy' }; return { grade: 'B', note: 'Partial policy' }; } },
  { header: 'x-frame-options', name: 'X-Frame-Options', weight: 10, check: function(v) { if (!v) return { grade: 'F', note: 'Missing — clickjacking risk' }; if (/DENY/i.test(v)) return { grade: 'A', note: 'DENY — strongest setting' }; if (/SAMEORIGIN/i.test(v)) return { grade: 'A', note: 'SAMEORIGIN — good' }; return { grade: 'C', note: 'Unusual value' }; } },
  { header: 'x-content-type-options', name: 'X-Content-Type-Options', weight: 10, check: function(v) { if (!v) return { grade: 'F', note: 'Missing — MIME sniffing risk' }; if (/nosniff/i.test(v)) return { grade: 'A', note: 'nosniff — correct' }; return { grade: 'C', note: 'Unexpected value' }; } },
  { header: 'referrer-policy', name: 'Referrer-Policy', weight: 8, check: function(v) { if (!v) return { grade: 'F', note: 'Missing — referrer leakage' }; if (/no-referrer|strict-origin|same-origin/i.test(v)) return { grade: 'A', note: 'Strict policy' }; return { grade: 'B', note: 'Present' }; } },
  { header: 'permissions-policy', name: 'Permissions-Policy', weight: 8, check: function(v) { if (!v) return { grade: 'D', note: 'Missing — browser features unrestricted' }; return { grade: 'A', note: 'Present — browser features restricted' }; } },
  { header: 'x-xss-protection', name: 'X-XSS-Protection', weight: 5, check: function(v) { if (!v) return { grade: 'D', note: 'Missing (legacy header, CSP preferred)' }; if (/1;\s*mode=block/i.test(v)) return { grade: 'A', note: '1; mode=block' }; if (v === '0') return { grade: 'B', note: 'Disabled (OK if CSP present)' }; return { grade: 'C', note: 'Present' }; } },
  { header: 'cross-origin-opener-policy', name: 'COOP', weight: 7, check: function(v) { if (!v) return { grade: 'D', note: 'Missing' }; if (/same-origin/i.test(v)) return { grade: 'A', note: 'same-origin' }; return { grade: 'B', note: 'Present' }; } },
  { header: 'cross-origin-resource-policy', name: 'CORP', weight: 7, check: function(v) { if (!v) return { grade: 'D', note: 'Missing' }; return { grade: 'A', note: 'Present' }; } },
  { header: 'cross-origin-embedder-policy', name: 'COEP', weight: 5, check: function(v) { if (!v) return { grade: 'D', note: 'Missing' }; return { grade: 'A', note: 'Present' }; } }
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function _vgLog(message, type) {
  type = type || 'info';
  var elapsed = _vgState.startTime ? ((performance.now() - _vgState.startTime) / 1000).toFixed(1) : '0.0';
  var entry = { time: elapsed, message: message, type: type };
  _vgState.log.push(entry);

  var logEl = document.getElementById('vg-log');
  if (!logEl) return;

  var colors = { info: '#8ab4d4', success: '#00ff88', warning: '#ffaa00', error: '#ff4444', phase: '#aa66ff', critical: '#ff2222', dim: '#4a6a8a', highlight: '#00ddff' };
  var color = colors[type] || colors.info;

  var line = document.createElement('div');
  line.style.cssText = 'margin:1px 0;white-space:pre-wrap;word-break:break-all;';
  line.innerHTML = '<span style="color:#3a5a7a;">[' + _vgPadTime(elapsed) + ']</span> <span style="color:' + color + ';">' + esc(message) + '</span>';
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function _vgPadTime(t) {
  var parts = t.split('.');
  var secs = parts[0];
  var ms = parts[1] || '0';
  var mins = Math.floor(parseInt(secs, 10) / 60);
  var s = parseInt(secs, 10) % 60;
  return (mins < 10 ? '0' : '') + mins + ':' + (s < 10 ? '0' : '') + s + '.' + ms;
}

function _vgUpdatePhase(phaseNum, status) {
  _vgState.phaseStatus[phaseNum] = status;
  _vgState.phase = phaseNum;

  for (var i = 0; i < _vgPhaseNames.length; i++) {
    var el = document.getElementById('vg-phase-' + i);
    if (!el) continue;
    var st = _vgState.phaseStatus[i] || 'pending';
    var bgColor = st === 'complete' ? '#00ff8815' : st === 'running' ? '#00aaff15' : st === 'error' ? '#ff444415' : '#0a0e14';
    var borderColor = st === 'complete' ? '#00ff88' : st === 'running' ? '#00aaff' : st === 'error' ? '#ff4444' : '#1a2a44';
    var textColor = st === 'complete' ? '#00ff88' : st === 'running' ? '#00ddff' : st === 'error' ? '#ff4444' : '#3a5a7a';
    var icon = st === 'complete' ? '✓' : st === 'running' ? '▸' : st === 'error' ? '✗' : '○';
    el.style.background = bgColor;
    el.style.borderColor = borderColor;
    el.querySelector('.vg-phase-icon').textContent = icon;
    el.querySelector('.vg-phase-icon').style.color = textColor;
    el.querySelector('.vg-phase-name').style.color = textColor;
  }

  // Update elapsed time
  var timeEl = document.getElementById('vg-elapsed');
  if (timeEl && _vgState.startTime) {
    var elapsed = ((performance.now() - _vgState.startTime) / 1000).toFixed(1);
    timeEl.textContent = _vgPadTime(elapsed);
  }
}

function _vgAddFinding(finding) {
  _vgState.findings.push(finding);
  var container = document.getElementById('vg-findings');
  if (!container) return;

  var sevColors = { critical: '#ff2222', high: '#ff6600', medium: '#ffaa00', low: '#44cc44', info: '#00aaff' };
  var color = sevColors[finding.severity] || sevColors.info;

  var card = document.createElement('div');
  card.style.cssText = 'background:' + color + '08;border:1px solid ' + color + '33;border-left:3px solid ' + color + ';border-radius:0 4px 4px 0;padding:8px 12px;margin:4px 0;font-size:10px;';
  card.innerHTML =
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">' +
    '<span style="color:' + color + ';font-weight:bold;font-size:9px;padding:1px 6px;background:' + color + '15;border:1px solid ' + color + '33;border-radius:2px;text-transform:uppercase;">' + esc(finding.severity) + '</span>' +
    '<span style="color:#3a5a7a;font-size:8px;">' + esc(finding.phase || '') + '</span>' +
    '</div>' +
    '<div style="color:#c8d6e5;font-weight:bold;margin-bottom:2px;">' + esc(finding.title) + '</div>' +
    '<div style="color:#6a8aaa;">' + esc(finding.description) + '</div>' +
    (finding.host ? '<div style="color:#4a6a8a;font-size:9px;margin-top:3px;">Host: ' + esc(finding.host) + '</div>' : '') +
    (finding.remediation ? '<div style="color:#00cc88;font-size:9px;margin-top:3px;">Fix: ' + esc(finding.remediation) + '</div>' : '');
  container.appendChild(card);

  // Update finding count
  var countEl = document.getElementById('vg-finding-count');
  if (countEl) countEl.textContent = _vgState.findings.length;
}

function _vgDnsQuery(domain, type) {
  return fetch('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + type)
    .then(function(r) { return r.json(); })
    .then(function(data) { return data; })
    .catch(function() { return { Status: -1, Answer: [] }; });
}

// ============================================================================
// RENDER FUNCTION
// ============================================================================
window.renderVanguard = function(container) {
  // Reset state
  _vgState = {
    target: null, running: false, aborted: false, phase: 0, totalPhases: 10,
    results: { dns: null, subdomains: null, hosts: null, tech: null, security: null, vulns: null, infra: null, email: null, score: null, report: null },
    log: [], startTime: null, findings: [], phaseStatus: []
  };
  for (var i = 0; i < 10; i++) _vgState.phaseStatus.push('pending');

  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',\'JetBrains Mono\',monospace;padding:0;min-height:100vh;">';

  // === HEADER ===
  h += '<div style="background:linear-gradient(135deg,#080c18,#0a1020);border-bottom:1px solid #1a3a5a;padding:20px 24px;">';
  h += '<div style="display:flex;align-items:center;gap:16px;">';
  h += '<div style="font-size:28px;font-weight:900;letter-spacing:4px;color:#00ddff;text-shadow:0 0 30px rgba(0,212,255,0.3);">VANGUARD</div>';
  h += '<div style="height:28px;width:1px;background:#1a3a5a;"></div>';
  h += '<div>';
  h += '<div style="font-size:11px;color:#6a8aaa;letter-spacing:2px;">AUTONOMOUS ATTACK SURFACE INTELLIGENCE</div>';
  h += '<div style="font-size:9px;color:#3a5a7a;letter-spacing:1px;margin-top:2px;">FOR AUTHORIZED PENETRATION TESTING ONLY</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // === TARGET INPUT ===
  h += '<div style="padding:16px 24px;background:#080c14;border-bottom:1px solid #0f1a24;">';
  h += '<div style="display:flex;gap:8px;align-items:center;">';
  h += '<div style="color:#4a6a8a;font-size:11px;letter-spacing:1px;flex-shrink:0;">TARGET:</div>';
  h += '<input id="vg-target" style="flex:1;background:#060a10;border:1px solid #1a3a5a;border-radius:4px;color:#00ddff;font-family:monospace;font-size:14px;padding:10px 14px;outline:none;" placeholder="example.com" spellcheck="false" autocomplete="off">';
  h += '<button onclick="_vgLaunchRecon()" id="vg-launch-btn" style="background:linear-gradient(135deg,#00aaff22,#00aaff11);color:#00ddff;border:1px solid #00aaff;padding:10px 24px;font-family:monospace;font-size:12px;font-weight:bold;cursor:pointer;border-radius:4px;letter-spacing:2px;transition:all 0.2s;">LAUNCH RECON</button>';
  h += '<button onclick="_vgAbort()" style="background:#ff444415;color:#ff4444;border:1px solid #ff444444;padding:10px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;letter-spacing:1px;">ABORT</button>';
  h += '</div>';

  // Authorization reminder
  h += '<div style="background:#ff444408;border:1px solid #ff444422;border-radius:4px;padding:6px 12px;margin-top:8px;font-size:9px;color:#ff6644;">';
  h += '⚠ LEGAL NOTICE: Only scan domains you own or have explicit written authorization to test. Unauthorized scanning violates the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent international laws.';
  h += '</div>';
  h += '</div>';

  // === PROGRESS DASHBOARD ===
  h += '<div style="padding:12px 24px;background:#060a10;border-bottom:1px solid #0f1a24;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
  h += '<div style="display:flex;align-items:center;gap:10px;">';
  h += '<span style="color:#4a6a8a;font-size:10px;letter-spacing:1px;">ELAPSED:</span>';
  h += '<span id="vg-elapsed" style="color:#00ddff;font-size:13px;font-weight:bold;">00:00.0</span>';
  h += '</div>';
  h += '<div style="display:flex;align-items:center;gap:10px;">';
  h += '<span style="color:#4a6a8a;font-size:10px;letter-spacing:1px;">FINDINGS:</span>';
  h += '<span id="vg-finding-count" style="color:#ff6600;font-size:13px;font-weight:bold;">0</span>';
  h += '</div>';
  h += '<div id="vg-status" style="color:#3a5a7a;font-size:10px;letter-spacing:1px;">AWAITING TARGET</div>';
  h += '</div>';

  // Phase indicators
  h += '<div style="display:flex;gap:3px;overflow-x:auto;">';
  for (var p = 0; p < _vgPhaseNames.length; p++) {
    h += '<div id="vg-phase-' + p + '" style="flex:1;min-width:80px;background:#0a0e14;border:1px solid #1a2a44;border-radius:3px;padding:4px 6px;text-align:center;transition:all 0.3s;">';
    h += '<div class="vg-phase-icon" style="color:#3a5a7a;font-size:11px;">○</div>';
    h += '<div class="vg-phase-name" style="color:#3a5a7a;font-size:7px;letter-spacing:0.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + (p + 1) + '. ' + esc(_vgPhaseNames[p].split(' ')[0]) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // === MAIN CONTENT: LOG + FINDINGS SIDE BY SIDE ===
  h += '<div style="display:flex;gap:0;min-height:500px;">';

  // Live log (left)
  h += '<div style="flex:1;border-right:1px solid #0f1a24;display:flex;flex-direction:column;">';
  h += '<div style="padding:8px 16px;background:#060a10;border-bottom:1px solid #0f1a24;font-size:10px;color:#4a6a8a;letter-spacing:1px;flex-shrink:0;">OPERATION LOG</div>';
  h += '<div id="vg-log" style="flex:1;padding:8px 12px;background:#040810;font-size:10px;line-height:1.6;overflow-y:auto;max-height:600px;"></div>';
  h += '</div>';

  // Findings (right)
  h += '<div style="flex:1;display:flex;flex-direction:column;">';
  h += '<div style="padding:8px 16px;background:#060a10;border-bottom:1px solid #0f1a24;font-size:10px;color:#4a6a8a;letter-spacing:1px;flex-shrink:0;">FINDINGS</div>';
  h += '<div id="vg-findings" style="flex:1;padding:8px 12px;background:#050a10;overflow-y:auto;max-height:600px;"></div>';
  h += '</div>';

  h += '</div>';

  // === PHASE RESULTS (expandable sections) ===
  h += '<div id="vg-phase-results" style="padding:0 24px 24px;"></div>';

  h += '</div>';

  container.innerHTML = h;

  // Focus input
  var input = document.getElementById('vg-target');
  if (input) {
    input.addEventListener('keydown', function(e) { if (e.key === 'Enter') _vgLaunchRecon(); });
    input.focus();
  }
};

// ============================================================================
// LAUNCH RECON — Main pipeline orchestrator
// ============================================================================
window._vgLaunchRecon = function() {
  var input = document.getElementById('vg-target');
  if (!input || !input.value.trim()) return;

  var target = input.value.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:.*$/, '');

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(target)) {
    _vgLog('ERROR: Invalid domain format — enter a domain like example.com', 'error');
    return;
  }

  if (_vgState.running) {
    _vgLog('Scan already in progress. Use ABORT to cancel.', 'warning');
    return;
  }

  _vgState.target = target;
  _vgState.running = true;
  _vgState.aborted = false;
  _vgState.startTime = performance.now();
  _vgState.findings = [];
  _vgState.log = [];

  // Clear UI
  var logEl = document.getElementById('vg-log');
  if (logEl) logEl.innerHTML = '';
  var findingsEl = document.getElementById('vg-findings');
  if (findingsEl) findingsEl.innerHTML = '';
  var resultsEl = document.getElementById('vg-phase-results');
  if (resultsEl) resultsEl.innerHTML = '';
  var countEl = document.getElementById('vg-finding-count');
  if (countEl) countEl.textContent = '0';

  var statusEl = document.getElementById('vg-status');
  if (statusEl) { statusEl.textContent = 'SCANNING'; statusEl.style.color = '#00ddff'; }

  // Disable launch button
  var btn = document.getElementById('vg-launch-btn');
  if (btn) { btn.disabled = true; btn.style.opacity = '0.4'; }

  // Start elapsed timer
  _vgElapsedTimer = setInterval(function() {
    var el = document.getElementById('vg-elapsed');
    if (el && _vgState.startTime) {
      el.textContent = _vgPadTime(((performance.now() - _vgState.startTime) / 1000).toFixed(1));
    }
  }, 100);

  // Banner
  _vgLog('', 'dim');
  _vgLog('██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗', 'highlight');
  _vgLog('██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗', 'highlight');
  _vgLog('██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║', 'highlight');
  _vgLog('╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║', 'highlight');
  _vgLog(' ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝', 'highlight');
  _vgLog('  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝', 'highlight');
  _vgLog('', 'dim');
  _vgLog('VANGUARD v1.0 — AUTONOMOUS ATTACK SURFACE INTELLIGENCE ENGINE', 'highlight');
  _vgLog('Darknode Platform — For Authorized Security Testing Only', 'dim');
  _vgLog('', 'dim');
  _vgLog('TARGET ACQUIRED: ' + target, 'success');
  _vgLog('SCAN INITIATED: ' + new Date().toISOString(), 'info');
  _vgLog('═══════════════════════════════════════════════════════════════', 'dim');

  // Launch pipeline
  _vgPhase1_DNS(target)
    .then(function() { if (_vgState.aborted) return; return _vgPhase2_Subdomains(target); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase3_HostProbe(); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase4_TechFingerprint(); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase5_Security(); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase6_Vulns(); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase7_Infra(); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase8_Email(); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase9_Score(); })
    .then(function() { if (_vgState.aborted) return; return _vgPhase10_Report(); })
    .then(function() {
      if (_vgState.aborted) return;

      var sc = _vgState.results.score || {};
      var subs = _vgState.results.subdomains || [];
      var alive = (_vgState.results.hosts || []).filter(function(h) { return h.alive; });
      var techs = (_vgState.results.tech || []).reduce(function(s, t) { return s + t.technologies.length; }, 0);
      var vulns = (_vgState.results.vulns || []).length;
      var elapsed = _vgFormatElapsed();

      _vgLog('', 'dim');
      _vgLog('═══════════════════════════════════════════════════════════════', 'highlight');
      _vgLog('VANGUARD SCAN COMPLETE', 'highlight');
      _vgLog('TARGET: ' + _vgState.target, 'info');
      _vgLog('RISK SCORE: ' + (sc.score || 0) + '/100 [' + (sc.level || 'N/A') + ']', sc.score > 60 ? 'critical' : sc.score > 40 ? 'warning' : 'success');
      _vgLog('FINDINGS: ' + (sc.findings ? sc.findings.critical : 0) + ' Critical, ' + (sc.findings ? sc.findings.high : 0) + ' High, ' + (sc.findings ? sc.findings.medium : 0) + ' Medium, ' + (sc.findings ? sc.findings.low : 0) + ' Low', 'info');
      _vgLog('SUBDOMAINS: ' + subs.length + ' discovered, ' + alive.length + ' alive', 'info');
      _vgLog('TECHNOLOGIES: ' + techs + ' detected', 'info');
      _vgLog('CVEs: ' + vulns + ' correlated', 'info');
      _vgLog('ELAPSED: ' + elapsed, 'info');
      _vgLog('═══════════════════════════════════════════════════════════════', 'highlight');

      _vgState.running = false;
      clearInterval(_vgElapsedTimer);
      var statusEl2 = document.getElementById('vg-status');
      if (statusEl2) { statusEl2.textContent = 'COMPLETE'; statusEl2.style.color = '#00ff88'; }
      var btn2 = document.getElementById('vg-launch-btn');
      if (btn2) { btn2.disabled = false; btn2.style.opacity = '1'; }

      _vgRenderPhaseResults();
    })
    .catch(function(err) {
      _vgLog('FATAL ERROR: ' + String(err.message || err), 'error');
      _vgState.running = false;
      clearInterval(_vgElapsedTimer);
      var statusEl3 = document.getElementById('vg-status');
      if (statusEl3) { statusEl3.textContent = 'ERROR'; statusEl3.style.color = '#ff4444'; }
      var btn3 = document.getElementById('vg-launch-btn');
      if (btn3) { btn3.disabled = false; btn3.style.opacity = '1'; }
    });
};

var _vgElapsedTimer = null;

window._vgAbort = function() {
  if (!_vgState.running) return;
  _vgState.aborted = true;
  _vgState.running = false;
  clearInterval(_vgElapsedTimer);
  _vgLog('', 'dim');
  _vgLog('██ SCAN ABORTED BY OPERATOR ██', 'error');
  var statusEl = document.getElementById('vg-status');
  if (statusEl) { statusEl.textContent = 'ABORTED'; statusEl.style.color = '#ff4444'; }
  var btn = document.getElementById('vg-launch-btn');
  if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
};

// ============================================================================
// PHASE 1: TARGET ACQUISITION — DNS RECONNAISSANCE
// ============================================================================
function _vgPhase1_DNS(domain) {
  return new Promise(function(resolve, reject) {
    if (_vgState.aborted) return resolve();
    _vgUpdatePhase(0, 'running');
    _vgLog('', 'dim');
    _vgLog('PHASE 1: TARGET ACQUISITION — DNS RECONNAISSANCE', 'phase');
    _vgLog('Enumerating all DNS record types for ' + domain, 'info');

    var recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA', 'SRV'];
    var dnsResults = {};
    var completed = 0;

    recordTypes.forEach(function(type) {
      _vgLog('  Querying ' + type + ' records...', 'dim');
      _vgDnsQuery(domain, type).then(function(data) {
        var answers = data.Answer || [];
        dnsResults[type] = answers;

        if (answers.length > 0) {
          answers.forEach(function(a) {
            _vgLog('  → [' + type + '] ' + (a.data || a.name || ''), 'success');
          });
        } else {
          _vgLog('  → [' + type + '] No records', 'dim');
        }

        // Extract findings
        if (type === 'TXT') {
          var hasSPF = false;
          answers.forEach(function(a) {
            var txt = (a.data || '').replace(/"/g, '');
            if (/v=spf1/i.test(txt)) {
              hasSPF = true;
              _vgLog('  ▸ SPF record found: ' + txt.substring(0, 80), 'info');
            }
            if (/v=DMARC1/i.test(txt)) {
              _vgLog('  ▸ DMARC record detected in base TXT', 'info');
            }
          });
          if (!hasSPF) {
            _vgAddFinding({ severity: 'medium', title: 'No SPF Record', description: 'Domain lacks SPF DNS record — email spoofing is possible.', phase: 'DNS', host: domain, remediation: 'Add a TXT record with v=spf1 policy' });
          }
        }

        if (type === 'MX') {
          if (answers.length === 0) {
            _vgLog('  ▸ No mail servers — domain may not receive email', 'warning');
          }
        }

        if (type === 'CAA') {
          if (answers.length === 0) {
            _vgAddFinding({ severity: 'low', title: 'No CAA Records', description: 'No Certificate Authority Authorization records — any CA can issue certificates for this domain.', phase: 'DNS', host: domain, remediation: 'Add CAA records to restrict which CAs can issue certificates' });
          }
        }

        completed++;
        if (completed >= recordTypes.length) {
          // Also check DMARC
          _vgDnsQuery('_dmarc.' + domain, 'TXT').then(function(dmarcData) {
            var dmarcAnswers = dmarcData.Answer || [];
            var hasDMARC = false;
            dmarcAnswers.forEach(function(a) {
              var txt = (a.data || '').replace(/"/g, '');
              if (/v=DMARC1/i.test(txt)) {
                hasDMARC = true;
                var policy = (txt.match(/p=(\w+)/i) || [])[1] || 'none';
                _vgLog('  ▸ DMARC policy: p=' + policy, policy === 'reject' ? 'success' : 'warning');
                if (policy === 'none') {
                  _vgAddFinding({ severity: 'medium', title: 'Weak DMARC Policy (p=none)', description: 'DMARC policy is set to none — spoofed emails are not rejected.', phase: 'DNS', host: domain, remediation: 'Change DMARC policy to p=quarantine or p=reject' });
                }
              }
            });
            if (!hasDMARC) {
              _vgAddFinding({ severity: 'medium', title: 'No DMARC Record', description: 'Domain lacks DMARC policy — email authentication results are not enforced.', phase: 'DNS', host: domain, remediation: 'Add _dmarc.' + domain + ' TXT record with DMARC policy' });
            }

            dnsResults.DMARC = dmarcAnswers;

            var totalRecords = 0;
            Object.keys(dnsResults).forEach(function(k) { totalRecords += dnsResults[k].length; });
            _vgLog('', 'dim');
            _vgLog('PHASE 1 COMPLETE — ' + totalRecords + ' DNS records enumerated', 'success');

            _vgState.results.dns = dnsResults;
            _vgUpdatePhase(0, 'complete');
            resolve();
          });
        }
      });
    });
  });
}

// ============================================================================
// PHASE 2: SUBDOMAIN DISCOVERY
// ============================================================================
function _vgPhase2_Subdomains(domain) {
  return new Promise(function(resolve) {
    if (_vgState.aborted) return resolve();
    _vgUpdatePhase(1, 'running');
    _vgLog('', 'dim');
    _vgLog('═══════════════════════════════════════════════════════════════', 'dim');
    _vgLog('PHASE 2: SUBDOMAIN DISCOVERY', 'phase');

    var subdomains = {};
    var liveSubdomains = [];

    // Step 1: Certificate Transparency
    _vgLog('Searching certificate transparency logs (crt.sh)...', 'info');

    fetch('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json')
      .then(function(r) { return r.json(); })
      .then(function(certs) {
        _vgLog('  → Found ' + certs.length + ' certificate entries', 'success');
        certs.forEach(function(cert) {
          var names = (cert.common_name || '') + '\n' + (cert.name_value || '');
          names.split(/[\n\s]+/).forEach(function(name) {
            name = name.trim().toLowerCase().replace(/^\*\./, '');
            if (name && name.indexOf(domain) !== -1 && name.indexOf('@') === -1) {
              subdomains[name] = 'crt.sh';
            }
          });
        });
        var ctCount = Object.keys(subdomains).length;
        _vgLog('  → ' + ctCount + ' unique subdomains from CT logs', 'info');
        _vgPhase2_BruteForce(domain, subdomains, resolve);
      })
      .catch(function(err) {
        _vgLog('  → crt.sh unavailable: ' + (err.message || 'CORS/network error'), 'warning');
        _vgPhase2_BruteForce(domain, subdomains, resolve);
      });
  });
}

function _vgPhase2_BruteForce(domain, subdomains, resolve) {
  if (_vgState.aborted) return resolve();

  _vgLog('Brute-forcing ' + _vgSubdomainWordlist.length + ' common subdomains via DNS...', 'info');

  var completed = 0;
  var total = _vgSubdomainWordlist.length;
  var batchSize = 10;
  var idx = 0;

  function processBatch() {
    if (_vgState.aborted) return resolve();
    var batch = _vgSubdomainWordlist.slice(idx, idx + batchSize);
    if (batch.length === 0) {
      // All done
      finishPhase2();
      return;
    }

    var batchPromises = batch.map(function(sub) {
      var fqdn = sub + '.' + _vgState.target;
      return _vgDnsQuery(fqdn, 'A').then(function(data) {
        completed++;
        if (data.Answer && data.Answer.length > 0) {
          subdomains[fqdn] = 'brute-force';
          var ip = data.Answer[0].data;
          _vgLog('  → [FOUND] ' + fqdn + ' → ' + ip, 'success');
        }
        // Progress update every 20
        if (completed % 20 === 0) {
          _vgLog('  ... ' + completed + '/' + total + ' checked', 'dim');
        }
      });
    });

    Promise.all(batchPromises).then(function() {
      idx += batchSize;
      setTimeout(processBatch, 50); // small delay to avoid rate limiting
    });
  }

  function finishPhase2() {
    var allSubs = Object.keys(subdomains);
    _vgState.results.subdomains = allSubs.map(function(s) { return { name: s, source: subdomains[s] }; });

    _vgLog('', 'dim');
    _vgLog('PHASE 2 COMPLETE — ' + allSubs.length + ' subdomains discovered', 'success');
    if (allSubs.length > 20) {
      _vgAddFinding({ severity: 'info', title: 'Large Attack Surface', description: allSubs.length + ' subdomains discovered — large attack surface increases risk.', phase: 'Subdomain Discovery', host: _vgState.target });
    }
    _vgUpdatePhase(1, 'complete');
    resolve();
  }

  processBatch();
}

// ============================================================================
// PHASE 3: HOST PROBING
// ============================================================================
function _vgPhase3_HostProbe() {
  return new Promise(function(resolve) {
    if (_vgState.aborted) return resolve();
    _vgUpdatePhase(2, 'running');
    _vgLog('', 'dim');
    _vgLog('═══════════════════════════════════════════════════════════════', 'dim');
    _vgLog('PHASE 3: HOST PROBING', 'phase');

    var subs = _vgState.results.subdomains || [];
    if (subs.length === 0) {
      subs = [{ name: _vgState.target, source: 'primary' }];
    }

    // Cap at 50 hosts to avoid excessive requests
    var toProbe = subs.slice(0, 50);
    _vgLog('Probing ' + toProbe.length + ' hosts for HTTP/HTTPS...', 'info');

    var hosts = [];
    var completed = 0;
    var idx = 0;
    var batchSize = 5;

    function probeBatch() {
      if (_vgState.aborted) return resolve();
      var batch = toProbe.slice(idx, idx + batchSize);
      if (batch.length === 0) {
        finishPhase3();
        return;
      }

      var batchPromises = batch.map(function(sub) {
        var host = sub.name;
        var startTime = performance.now();

        return fetch('https://' + host, { mode: 'cors', redirect: 'follow', signal: AbortSignal.timeout(5000) })
          .then(function(resp) {
            var elapsed = Math.round(performance.now() - startTime);
            var entry = { host: host, protocol: 'https', status: resp.status, time: elapsed, alive: true, headers: resp.headers, url: resp.url };
            hosts.push(entry);
            _vgLog('  → [ALIVE] https://' + host + ' — ' + resp.status + ' (' + elapsed + 'ms)', 'success');
            completed++;
            return entry;
          })
          .catch(function() {
            // Try HTTP
            return fetch('http://' + host, { mode: 'cors', redirect: 'follow', signal: AbortSignal.timeout(5000) })
              .then(function(resp2) {
                var elapsed2 = Math.round(performance.now() - startTime);
                var entry2 = { host: host, protocol: 'http', status: resp2.status, time: elapsed2, alive: true, headers: resp2.headers, url: resp2.url };
                hosts.push(entry2);
                _vgLog('  → [ALIVE] http://' + host + ' — ' + resp2.status + ' (' + elapsed2 + 'ms)', 'warning');
                _vgAddFinding({ severity: 'medium', title: 'HTTP Only (No HTTPS)', description: host + ' responds on HTTP but not HTTPS — traffic is unencrypted.', phase: 'Host Probe', host: host, remediation: 'Enable HTTPS with a valid TLS certificate' });
                completed++;
                return entry2;
              })
              .catch(function() {
                var elapsed3 = Math.round(performance.now() - startTime);
                hosts.push({ host: host, protocol: 'none', status: 0, time: elapsed3, alive: false });
                completed++;
                return null;
              });
          });
      });

      Promise.all(batchPromises).then(function() {
        idx += batchSize;
        if (completed % 10 === 0 && completed > 0) {
          _vgLog('  ... ' + completed + '/' + toProbe.length + ' probed', 'dim');
        }
        setTimeout(probeBatch, 100);
      });
    }

    function finishPhase3() {
      _vgState.results.hosts = hosts;
      var alive = hosts.filter(function(h) { return h.alive; }).length;
      _vgLog('', 'dim');
      _vgLog('PHASE 3 COMPLETE — ' + alive + '/' + hosts.length + ' hosts alive', 'success');
      _vgUpdatePhase(2, 'complete');
      resolve();
    }

    probeBatch();
  });
}

// ============================================================================
// PHASE 4: TECHNOLOGY FINGERPRINTING
// ============================================================================
function _vgPhase4_TechFingerprint() {
  return new Promise(function(resolve) {
    if (_vgState.aborted) return resolve();
    _vgUpdatePhase(3, 'running');
    _vgLog('', 'dim');
    _vgLog('═══════════════════════════════════════════════════════════════', 'dim');
    _vgLog('PHASE 4: TECHNOLOGY FINGERPRINTING', 'phase');

    var aliveHosts = (_vgState.results.hosts || []).filter(function(h) { return h.alive && h.headers; });

    if (aliveHosts.length === 0) {
      _vgLog('  No alive hosts with accessible headers — skipping', 'warning');
      _vgState.results.tech = [];
      _vgUpdatePhase(3, 'complete');
      return resolve();
    }

    _vgLog('Fingerprinting ' + aliveHosts.length + ' alive hosts...', 'info');

    var techResults = [];

    aliveHosts.forEach(function(hostEntry) {
      var detected = [];
      var headers = hostEntry.headers;

      _vgTechSignatures.forEach(function(sig) {
        try {
          if (sig.detect(headers)) {
            detected.push({ name: sig.name, category: sig.category });
          }
        } catch (e) {}
      });

      // Extract raw server info
      var serverHeader = null;
      var poweredBy = null;
      try { serverHeader = headers.get('server'); } catch (e) {}
      try { poweredBy = headers.get('x-powered-by'); } catch (e) {}

      if (detected.length > 0) {
        var techNames = detected.map(function(d) { return d.name; }).join(', ');
        _vgLog('  → [' + hostEntry.host + '] ' + techNames, 'success');
      }

      // Check for server version disclosure
      if (serverHeader && /\/\d/.test(serverHeader)) {
        _vgAddFinding({ severity: 'low', title: 'Server Version Disclosed', description: 'Server header reveals version: ' + serverHeader, phase: 'Tech Fingerprint', host: hostEntry.host, remediation: 'Remove or generalize the Server header to hide version information' });
        _vgLog('  ▸ Version disclosure: ' + serverHeader, 'warning');
      }

      if (poweredBy) {
        _vgAddFinding({ severity: 'low', title: 'X-Powered-By Exposed', description: 'X-Powered-By header reveals technology: ' + poweredBy, phase: 'Tech Fingerprint', host: hostEntry.host, remediation: 'Remove the X-Powered-By header' });
        _vgLog('  ▸ X-Powered-By: ' + poweredBy, 'warning');
      }

      techResults.push({ host: hostEntry.host, technologies: detected, server: serverHeader, poweredBy: poweredBy });
    });

    _vgState.results.tech = techResults;
    var totalTech = techResults.reduce(function(sum, t) { return sum + t.technologies.length; }, 0);
    _vgLog('', 'dim');
    _vgLog('PHASE 4 COMPLETE — ' + totalTech + ' technologies identified across ' + techResults.length + ' hosts', 'success');
    _vgUpdatePhase(3, 'complete');
    resolve();
  });
}

// ============================================================================
// PHASE 5: SECURITY ASSESSMENT
// ============================================================================
function _vgPhase5_Security() {
  return new Promise(function(resolve) {
    if (_vgState.aborted) return resolve();
    _vgUpdatePhase(4, 'running');
    _vgLog('', 'dim');
    _vgLog('═══════════════════════════════════════════════════════════════', 'dim');
    _vgLog('PHASE 5: SECURITY ASSESSMENT', 'phase');

    var aliveHosts = (_vgState.results.hosts || []).filter(function(h) { return h.alive && h.headers; });

    if (aliveHosts.length === 0) {
      _vgLog('  No accessible hosts — skipping', 'warning');
      _vgState.results.security = [];
      _vgUpdatePhase(4, 'complete');
      return resolve();
    }

    _vgLog('Analyzing security headers on ' + aliveHosts.length + ' hosts...', 'info');

    var secResults = [];

    aliveHosts.forEach(function(hostEntry) {
      var headers = hostEntry.headers;
      var headerChecks = [];
      var totalScore = 0;
      var maxScore = 0;

      _vgSecurityHeaders.forEach(function(check) {
        var value = null;
        try { value = headers.get(check.header); } catch (e) {}
        var result = check.check(value);

        var gradePoints = { A: 100, B: 75, C: 50, D: 25, F: 0 };
        var points = (gradePoints[result.grade] || 0) * (check.weight / 100);
        totalScore += points;
        maxScore += check.weight;

        headerChecks.push({ name: check.name, header: check.header, value: value, grade: result.grade, note: result.note, weight: check.weight });

        if (result.grade === 'F') {
          var severity = check.weight >= 15 ? 'high' : check.weight >= 10 ? 'medium' : 'low';
          _vgAddFinding({ severity: severity, title: 'Missing: ' + check.name, description: result.note, phase: 'Security', host: hostEntry.host, remediation: 'Add the ' + check.header + ' response header' });
        }
      });

      // CORS check
      var corsHeader = null;
      try { corsHeader = headers.get('access-control-allow-origin'); } catch (e) {}
      if (corsHeader === '*') {
        _vgAddFinding({ severity: 'medium', title: 'Wildcard CORS (Access-Control-Allow-Origin: *)', description: 'Any website can make cross-origin requests to this host.', phase: 'Security', host: hostEntry.host, remediation: 'Restrict CORS to specific trusted origins' });
        _vgLog('  ▸ [' + hostEntry.host + '] Wildcard CORS detected', 'warning');
      }

      // Overall grade
      var pct = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;
      var grade = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 50 ? 'C' : pct >= 25 ? 'D' : 'F';
      var gradeColor = { A: '#00ff88', B: '#44cc44', C: '#ffaa00', D: '#ff6600', F: '#ff2222' }[grade];

      _vgLog('  → [' + hostEntry.host + '] Security Grade: ' + grade + ' (' + pct + '%)', grade === 'A' || grade === 'B' ? 'success' : grade === 'C' ? 'warning' : 'error');

      // Log individual header statuses
      headerChecks.forEach(function(hc) {
        var icon = hc.grade === 'A' ? '✓' : hc.grade === 'F' ? '✗' : '~';
        var logType = hc.grade === 'A' || hc.grade === 'B' ? 'dim' : hc.grade === 'F' ? 'warning' : 'dim';
        _vgLog('    ' + icon + ' ' + hc.name + ': ' + hc.grade + ' — ' + hc.note, logType);
      });

      secResults.push({ host: hostEntry.host, headers: headerChecks, grade: grade, score: pct, cors: corsHeader });
    });

    _vgState.results.security = secResults;
    _vgLog('', 'dim');
    _vgLog('PHASE 5 COMPLETE — ' + secResults.length + ' hosts assessed', 'success');
    _vgUpdatePhase(4, 'complete');
    resolve();
  });
}

// ============================================================================
// PHASE 6: VULNERABILITY CORRELATION
// ============================================================================
var _vgBulletproofASNs = [48693,200019,57043,51159,210558,204957,9009,49505,210644,62904,395092,36352,22616,14618,16276];

function _vgPhase6_Vulns() {
  return new Promise(function(resolve) {
    _vgUpdatePhase(5, 'running');
    _vgLog('', 'dim');
    _vgLog('PHASE 6: VULNERABILITY CORRELATION', 'phase');
    _vgLog('Correlating detected technologies against NVD CVE database...', 'info');

    var techs = (_vgState.results.tech || []).reduce(function(all, h) {
      return all.concat(h.technologies.map(function(t) { return t.name; }));
    }, []);
    techs = techs.filter(function(t, i) { return techs.indexOf(t) === i; });

    if (techs.length === 0) {
      _vgLog('No technologies to correlate — skipping CVE search', 'warning');
      _vgState.results.vulns = [];
      _vgUpdatePhase(5, 'complete');
      resolve();
      return;
    }

    _vgLog('Querying NVD for ' + techs.length + ' technologies (6s rate limit per query)...', 'info');
    var vulnResults = [];
    var kevData = null;

    fetch('/data/feeds/cisa-kev.json').then(function(r) { return r.json(); }).then(function(d) { kevData = d.data || []; }).catch(function() { kevData = []; });

    var idx = 0;
    function nextTech() {
      if (_vgState.aborted || idx >= techs.length) {
        _vgState.results.vulns = vulnResults;
        _vgLog('', 'dim');
        _vgLog('PHASE 6 COMPLETE — ' + vulnResults.length + ' CVEs correlated across ' + techs.length + ' technologies', 'success');
        _vgUpdatePhase(5, 'complete');
        resolve();
        return;
      }
      var tech = techs[idx];
      idx++;
      _vgLog('  Querying NVD: ' + tech, 'dim');
      fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=' + encodeURIComponent(tech) + '&resultsPerPage=5')
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(data) {
          if (data && data.vulnerabilities) {
            data.vulnerabilities.forEach(function(v) {
              var cve = v.cve || {};
              var id = cve.id || 'UNKNOWN';
              var metrics = cve.metrics || {};
              var cvss31 = (metrics.cvssMetricV31 || [{}])[0];
              var score = cvss31.cvssData ? cvss31.cvssData.baseScore : 0;
              var severity = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
              var desc = ((cve.descriptions || []).find(function(d) { return d.lang === 'en'; }) || {}).value || '';
              var inKEV = kevData && kevData.some(function(k) { return k.cve === id; });
              vulnResults.push({ cve: id, score: score, severity: severity, tech: tech, description: desc.substring(0, 200), inKEV: inKEV });
              _vgAddFinding({ severity: severity, title: id + ' (' + score + ') — ' + tech, detail: desc.substring(0, 150), phase: 6, category: inKEV ? 'CISA KEV — ACTIVELY EXPLOITED' : 'CVE' });
              if (inKEV) _vgLog('  !! CISA KEV MATCH: ' + id + ' — actively exploited in the wild', 'critical');
            });
          }
          setTimeout(nextTech, 6200);
        })
        .catch(function() { setTimeout(nextTech, 6200); });
    }
    setTimeout(function() { nextTech(); }, 500);
  });
}

// ============================================================================
// PHASE 7: INFRASTRUCTURE ANALYSIS
// ============================================================================
function _vgPhase7_Infra() {
  return new Promise(function(resolve) {
    _vgUpdatePhase(6, 'running');
    _vgLog('', 'dim');
    _vgLog('PHASE 7: INFRASTRUCTURE ANALYSIS', 'phase');

    var hosts = (_vgState.results.hosts || []).filter(function(h) { return h.alive; });
    var ips = {};
    var dnsRecords = _vgState.results.dns || {};
    if (dnsRecords.A) dnsRecords.A.forEach(function(r) { ips[r.data] = [_vgState.target]; });
    hosts.forEach(function(h) { if (h.ip) { if (!ips[h.ip]) ips[h.ip] = []; ips[h.ip].push(h.host); } });

    var uniqueIPs = Object.keys(ips);
    if (uniqueIPs.length === 0) {
      _vgLog('No IPs to analyze — skipping', 'warning');
      _vgState.results.infra = [];
      _vgUpdatePhase(6, 'complete');
      resolve();
      return;
    }

    _vgLog('Analyzing ' + uniqueIPs.length + ' unique IP addresses...', 'info');
    var infraResults = [];
    var completed = 0;

    uniqueIPs.forEach(function(ip) {
      fetch('https://ipapi.co/' + ip + '/json/')
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(geo) {
          var entry = { ip: ip, hosts: ips[ip], geo: geo || {} };
          if (geo) {
            entry.country = geo.country_name || 'Unknown';
            entry.city = geo.city || '';
            entry.org = geo.org || '';
            entry.asn = geo.asn ? parseInt(String(geo.asn).replace('AS', ''), 10) : 0;
            var isBulletproof = _vgBulletproofASNs.indexOf(entry.asn) !== -1;
            entry.bulletproof = isBulletproof;
            var cloud = '';
            var orgLower = (geo.org || '').toLowerCase();
            if (orgLower.indexOf('amazon') !== -1 || orgLower.indexOf('aws') !== -1) cloud = 'AWS';
            else if (orgLower.indexOf('google') !== -1 || orgLower.indexOf('gcp') !== -1) cloud = 'GCP';
            else if (orgLower.indexOf('microsoft') !== -1 || orgLower.indexOf('azure') !== -1) cloud = 'Azure';
            else if (orgLower.indexOf('cloudflare') !== -1) cloud = 'Cloudflare';
            else if (orgLower.indexOf('digitalocean') !== -1) cloud = 'DigitalOcean';
            else if (orgLower.indexOf('hetzner') !== -1) cloud = 'Hetzner';
            else if (orgLower.indexOf('ovh') !== -1) cloud = 'OVH';
            entry.cloud = cloud;

            _vgLog('  ' + ip + ' → ' + entry.country + (entry.city ? ', ' + entry.city : '') + ' | ' + (cloud || entry.org) + (isBulletproof ? ' [BULLETPROOF HOSTING!]' : ''), isBulletproof ? 'critical' : 'info');
            if (isBulletproof) _vgAddFinding({ severity: 'high', title: 'Bulletproof hosting detected: ' + ip, detail: 'ASN ' + entry.asn + ' (' + entry.org + ') is known bulletproof hosting', phase: 7, category: 'INFRA' });
            if (ips[ip].length > 1) {
              _vgLog('  Shared hosting: ' + ips[ip].length + ' subdomains on ' + ip, 'warning');
              _vgAddFinding({ severity: 'info', title: 'Shared IP: ' + ips[ip].length + ' hosts on ' + ip, detail: ips[ip].join(', '), phase: 7, category: 'INFRA' });
            }
          }
          infraResults.push(entry);
          completed++;
          if (completed >= uniqueIPs.length) {
            _vgState.results.infra = infraResults;
            _vgLog('', 'dim');
            _vgLog('PHASE 7 COMPLETE — ' + infraResults.length + ' IPs geolocated', 'success');
            _vgUpdatePhase(6, 'complete');
            resolve();
          }
        })
        .catch(function() {
          infraResults.push({ ip: ip, hosts: ips[ip], geo: {}, error: true });
          completed++;
          if (completed >= uniqueIPs.length) {
            _vgState.results.infra = infraResults;
            _vgLog('PHASE 7 COMPLETE — ' + infraResults.length + ' IPs processed (' + infraResults.filter(function(i) { return i.error; }).length + ' errors)', 'success');
            _vgUpdatePhase(6, 'complete');
            resolve();
          }
        });
    });
  });
}

// ============================================================================
// PHASE 8: EMAIL SECURITY AUDIT
// ============================================================================
function _vgPhase8_Email() {
  return new Promise(function(resolve) {
    _vgUpdatePhase(7, 'running');
    _vgLog('', 'dim');
    _vgLog('PHASE 8: EMAIL SECURITY AUDIT', 'phase');
    var domain = _vgState.target;
    var emailResult = { domain: domain, spf: null, dmarc: null, dkim: [], mxServers: [], grade: 'F' };

    var dnsData = _vgState.results.dns || {};
    // Extract SPF from existing TXT records
    if (dnsData.TXT) {
      dnsData.TXT.forEach(function(r) {
        if (r.data && r.data.indexOf('v=spf1') !== -1) emailResult.spf = r.data.replace(/"/g, '');
      });
    }
    if (dnsData.MX) emailResult.mxServers = dnsData.MX.map(function(r) { return r.data; });

    if (emailResult.spf) _vgLog('  SPF: ' + emailResult.spf, 'info');
    else { _vgLog('  SPF: NOT FOUND — domain is vulnerable to email spoofing', 'critical'); _vgAddFinding({ severity: 'high', title: 'No SPF record', detail: 'Domain ' + domain + ' has no SPF record — emails can be spoofed', phase: 8, category: 'EMAIL' }); }

    // DMARC
    _vgDnsQuery('_dmarc.' + domain, 'TXT')
      .then(function(dmarcData) {
        if (dmarcData && dmarcData.Answer) {
          dmarcData.Answer.forEach(function(a) {
            if (a.data && a.data.indexOf('v=DMARC1') !== -1) emailResult.dmarc = a.data.replace(/"/g, '');
          });
        }
        if (emailResult.dmarc) {
          var policy = (emailResult.dmarc.match(/p=(\w+)/i) || [])[1] || 'none';
          _vgLog('  DMARC: p=' + policy + ' — ' + emailResult.dmarc.substring(0, 80), policy === 'reject' ? 'success' : policy === 'quarantine' ? 'warning' : 'critical');
          if (policy === 'none') _vgAddFinding({ severity: 'medium', title: 'DMARC policy is "none"', detail: 'DMARC exists but policy is "none" — spoofed emails are not rejected', phase: 8, category: 'EMAIL' });
        } else {
          _vgLog('  DMARC: NOT FOUND', 'critical');
          _vgAddFinding({ severity: 'high', title: 'No DMARC record', detail: 'Domain has no DMARC — no domain-based message authentication', phase: 8, category: 'EMAIL' });
        }

        // DKIM selector probing
        var dkimSelectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'mandrill', 'amazonses', 'sendgrid', 'mailchimp', 'dkim', 'mail'];
        var dkimDone = 0;
        _vgLog('  Probing ' + dkimSelectors.length + ' DKIM selectors...', 'dim');
        dkimSelectors.forEach(function(sel) {
          _vgDnsQuery(sel + '._domainkey.' + domain, 'TXT')
            .then(function(dkimData) {
              if (dkimData && dkimData.Answer && dkimData.Answer.length > 0) {
                emailResult.dkim.push({ selector: sel, record: (dkimData.Answer[0].data || '').substring(0, 100) });
                _vgLog('  DKIM found: selector=' + sel, 'success');
              }
              dkimDone++;
              if (dkimDone >= dkimSelectors.length) finishEmail();
            })
            .catch(function() { dkimDone++; if (dkimDone >= dkimSelectors.length) finishEmail(); });
        });

        function finishEmail() {
          // Grade
          var hasSpf = !!emailResult.spf;
          var hasDmarc = !!emailResult.dmarc;
          var dmarcStrong = hasDmarc && /p=(reject|quarantine)/i.test(emailResult.dmarc);
          var hasDkim = emailResult.dkim.length > 0;
          var spfStrong = hasSpf && /-all/.test(emailResult.spf);

          if (spfStrong && dmarcStrong && hasDkim) emailResult.grade = 'A';
          else if (hasSpf && hasDmarc && hasDkim) emailResult.grade = 'B';
          else if (hasSpf && hasDmarc) emailResult.grade = 'C';
          else if (hasSpf || hasDmarc) emailResult.grade = 'D';
          else emailResult.grade = 'F';

          var gc = { A: '#00ff88', B: '#44cc44', C: '#ffaa00', D: '#ff6600', F: '#ff2222' }[emailResult.grade];
          _vgLog('  Email Security Grade: ' + emailResult.grade + (emailResult.dkim.length > 0 ? ' (' + emailResult.dkim.length + ' DKIM selectors found)' : ''), emailResult.grade <= 'B' ? 'success' : emailResult.grade <= 'C' ? 'warning' : 'critical');
          _vgState.results.email = emailResult;
          _vgLog('', 'dim');
          _vgLog('PHASE 8 COMPLETE — Email security grade: ' + emailResult.grade, emailResult.grade <= 'C' ? 'success' : 'warning');
          _vgUpdatePhase(7, 'complete');
          resolve();
        }
      })
      .catch(function() {
        _vgState.results.email = emailResult;
        _vgLog('PHASE 8 COMPLETE (with errors)', 'warning');
        _vgUpdatePhase(7, 'complete');
        resolve();
      });
  });
}

// ============================================================================
// PHASE 9: ATTACK SURFACE SCORING
// ============================================================================
var _vgMitreTechniques = [
  { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
  { id: 'T1590', name: 'Gather Victim Network Information', tactic: 'Reconnaissance' },
  { id: 'T1592', name: 'Gather Victim Host Information', tactic: 'Reconnaissance' },
  { id: 'T1589', name: 'Gather Victim Identity Information', tactic: 'Reconnaissance' },
  { id: 'T1591', name: 'Gather Victim Org Information', tactic: 'Reconnaissance' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
  { id: 'T1566', name: 'Phishing', tactic: 'Initial Access' }
];

function _vgPhase9_Score() {
  return new Promise(function(resolve) {
    _vgUpdatePhase(8, 'running');
    _vgLog('', 'dim');
    _vgLog('PHASE 9: ATTACK SURFACE SCORING', 'phase');

    var score = 0;
    var reasons = [];

    var findings = _vgState.findings;
    var critCount = findings.filter(function(f) { return f.severity === 'critical'; }).length;
    var highCount = findings.filter(function(f) { return f.severity === 'high'; }).length;
    var medCount = findings.filter(function(f) { return f.severity === 'medium'; }).length;

    if (critCount > 0) { score += 30; reasons.push('+30 CRITICAL CVE/findings (' + critCount + ')'); }
    if (highCount > 0) { score += 20; reasons.push('+20 HIGH severity findings (' + highCount + ')'); }

    var secResults = _vgState.results.security || [];
    var worstGrade = 'A';
    secResults.forEach(function(s) { if (s.grade > worstGrade) worstGrade = s.grade; });
    if (worstGrade >= 'D') { score += 15; reasons.push('+15 Security headers grade: ' + worstGrade); }

    secResults.forEach(function(s) {
      if (s.headers) {
        if (!s.headers['content-security-policy']) { score += 5; reasons.push('+5 Missing CSP on ' + s.host); }
        if (!s.headers['strict-transport-security']) { score += 5; reasons.push('+5 Missing HSTS on ' + s.host); }
      }
      if (s.corsWildcard) { score += 10; reasons.push('+10 CORS wildcard on ' + s.host); }
    });

    var email = _vgState.results.email || {};
    if (email.grade >= 'D') { score += 10; reasons.push('+10 Email security grade: ' + email.grade); }

    var infra = _vgState.results.infra || [];
    infra.forEach(function(i) {
      if (i.bulletproof) { score += 5; reasons.push('+5 Bulletproof hosting: ' + i.ip); }
    });

    score = Math.min(100, score);
    var level = score <= 20 ? 'LOW' : score <= 40 ? 'MEDIUM' : score <= 60 ? 'HIGH' : score <= 80 ? 'CRITICAL' : 'SEVERE';
    var levelColor = score <= 20 ? '#00ff88' : score <= 40 ? '#ffcc00' : score <= 60 ? '#ff8800' : score <= 80 ? '#ff4444' : '#cc0000';

    // Map to MITRE
    var mitre = [];
    mitre.push(_vgMitreTechniques[0]); // T1595 Active Scanning
    mitre.push(_vgMitreTechniques[1]); // T1590 Network Info
    mitre.push(_vgMitreTechniques[2]); // T1592 Host Info
    if (email.grade >= 'D') mitre.push(_vgMitreTechniques[8]); // T1566 Phishing
    if (critCount > 0) mitre.push(_vgMitreTechniques[5]); // T1190 Exploit Public App

    _vgState.results.score = { score: score, level: level, color: levelColor, reasons: reasons, mitre: mitre, findings: { critical: critCount, high: highCount, medium: medCount, low: findings.filter(function(f) { return f.severity === 'low' || f.severity === 'info'; }).length } };

    _vgLog('', 'dim');
    reasons.forEach(function(r) { _vgLog('  ' + r, 'dim'); });
    _vgLog('', 'dim');
    _vgLog('RISK SCORE: ' + score + '/100 [' + level + ']', score > 60 ? 'critical' : score > 40 ? 'warning' : 'success');
    _vgLog('MITRE ATT&CK: ' + mitre.map(function(m) { return m.id; }).join(', '), 'info');
    _vgLog('', 'dim');
    _vgLog('PHASE 9 COMPLETE', 'success');
    _vgUpdatePhase(8, 'complete');
    resolve();
  });
}

// ============================================================================
// PHASE 10: REPORT GENERATION
// ============================================================================
function _vgPhase10_Report() {
  return new Promise(function(resolve) {
    _vgUpdatePhase(9, 'running');
    _vgLog('', 'dim');
    _vgLog('PHASE 10: REPORT GENERATION', 'phase');

    var sc = _vgState.results.score || {};
    var elapsed = _vgState.startTime ? ((performance.now() - _vgState.startTime) / 1000) : 0;
    var subs = _vgState.results.subdomains || [];
    var hosts = (_vgState.results.hosts || []).filter(function(h) { return h.alive; });
    var vulns = _vgState.results.vulns || [];
    var email = _vgState.results.email || {};
    var infra = _vgState.results.infra || [];

    var report = '<!doctype html><html><head><meta charset="utf-8"><title>VANGUARD Report — ' + esc(_vgState.target) + '</title>';
    report += '<style>body{background:#0a0e14;color:#c8d6e5;font-family:"Courier New",monospace;padding:30px;margin:0}h1{color:#00ddff;letter-spacing:3px}h2{color:#00aaff;border-bottom:1px solid #1a3a5a;padding-bottom:6px;margin-top:30px}';
    report += '.card{background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin:10px 0}.crit{color:#ff2222}.high{color:#ff6600}.med{color:#ffaa00}.low{color:#00cc88}.info{color:#4a6a8a}';
    report += 'table{width:100%;border-collapse:collapse;font-size:11px}th{text-align:left;padding:6px;color:#00aaff;border-bottom:2px solid #1a3a5a}td{padding:5px 6px;border-bottom:1px solid #0d1525}';
    report += '.score{font-size:60px;font-weight:bold;text-align:center;padding:20px}</style></head><body>';
    report += '<h1>VANGUARD — ATTACK SURFACE INTELLIGENCE REPORT</h1>';
    report += '<div class="card"><strong>Target:</strong> ' + esc(_vgState.target) + ' | <strong>Date:</strong> ' + new Date().toISOString().substring(0, 19) + 'Z | <strong>Duration:</strong> ' + Math.round(elapsed) + 's | <strong>Engine:</strong> VANGUARD v1.0</div>';
    report += '<div class="card"><div class="score" style="color:' + sc.color + '">' + sc.score + '/100</div><div style="text-align:center;font-size:18px;color:' + sc.color + '">' + sc.level + '</div></div>';

    // Findings summary
    report += '<h2>FINDINGS SUMMARY</h2><div class="card">';
    report += '<table><tr><th>Severity</th><th>Count</th></tr>';
    var fc = sc.findings || {};
    report += '<tr><td class="crit">CRITICAL</td><td>' + (fc.critical || 0) + '</td></tr>';
    report += '<tr><td class="high">HIGH</td><td>' + (fc.high || 0) + '</td></tr>';
    report += '<tr><td class="med">MEDIUM</td><td>' + (fc.medium || 0) + '</td></tr>';
    report += '<tr><td class="low">LOW/INFO</td><td>' + (fc.low || 0) + '</td></tr>';
    report += '</table></div>';

    // All findings
    report += '<h2>DETAILED FINDINGS (' + _vgState.findings.length + ')</h2><div class="card"><table><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Phase</th></tr>';
    var sorted = _vgState.findings.slice().sort(function(a, b) {
      var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    });
    sorted.forEach(function(f) {
      var cls = f.severity === 'critical' ? 'crit' : f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'med' : 'low';
      report += '<tr><td class="' + cls + '">' + esc(f.severity).toUpperCase() + '</td><td>' + esc(f.title) + '</td><td style="color:#6a8aaa;font-size:10px">' + esc(f.detail || '') + '</td><td>' + (f.phase || '') + '</td></tr>';
    });
    report += '</table></div>';

    // Subdomains
    report += '<h2>SUBDOMAINS (' + subs.length + ')</h2><div class="card">';
    subs.forEach(function(s) { report += '<div style="font-size:10px">' + esc(s.name) + '</div>'; });
    report += '</div>';

    // Vulns
    if (vulns.length > 0) {
      report += '<h2>CVE CORRELATION (' + vulns.length + ')</h2><div class="card"><table><tr><th>CVE</th><th>Score</th><th>Technology</th><th>KEV</th></tr>';
      vulns.forEach(function(v) {
        var cls = v.severity === 'critical' ? 'crit' : v.severity === 'high' ? 'high' : 'med';
        report += '<tr><td class="' + cls + '">' + esc(v.cve) + '</td><td>' + v.score + '</td><td>' + esc(v.tech) + '</td><td>' + (v.inKEV ? '<span class="crit">YES</span>' : 'No') + '</td></tr>';
      });
      report += '</table></div>';
    }

    // Email
    report += '<h2>EMAIL SECURITY</h2><div class="card">';
    var egc = { A: '#00ff88', B: '#44cc44', C: '#ffaa00', D: '#ff6600', F: '#ff2222' }[email.grade] || '#4a6a8a';
    report += '<div style="font-size:36px;font-weight:bold;color:' + egc + ';text-align:center">' + (email.grade || 'N/A') + '</div>';
    report += '<div style="font-size:11px">SPF: ' + esc(email.spf || 'NOT FOUND') + '</div>';
    report += '<div style="font-size:11px">DMARC: ' + esc(email.dmarc || 'NOT FOUND') + '</div>';
    report += '<div style="font-size:11px">DKIM selectors: ' + (email.dkim || []).length + '</div>';
    report += '</div>';

    // MITRE
    report += '<h2>MITRE ATT&CK MAPPING</h2><div class="card"><table><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr>';
    (sc.mitre || []).forEach(function(m) {
      report += '<tr><td style="color:#00aaff">' + esc(m.id) + '</td><td>' + esc(m.name) + '</td><td style="color:#4a6a8a">' + esc(m.tactic) + '</td></tr>';
    });
    report += '</table></div>';

    report += '<div style="margin-top:30px;text-align:center;color:#3a5a7a;font-size:10px">Generated by VANGUARD — Darknode Autonomous Attack Surface Intelligence Engine<br>FOR AUTHORIZED SECURITY TESTING ONLY</div>';
    report += '</body></html>';

    _vgState.results.report = report;
    _vgLog('Report generated (' + Math.round(report.length / 1024) + ' KB)', 'success');
    _vgLog('', 'dim');
    _vgLog('PHASE 10 COMPLETE', 'success');
    _vgUpdatePhase(9, 'complete');
    resolve();
  });
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
function _vgFormatElapsed() {
  if (!_vgState.startTime) return '00:00.0';
  var secs = (performance.now() - _vgState.startTime) / 1000;
  var mins = Math.floor(secs / 60);
  var s = (secs % 60).toFixed(1);
  return (mins < 10 ? '0' : '') + mins + ':' + (s < 10 ? '0' : '') + s;
}

// ============================================================================
// PHASE RESULTS RENDERER
// ============================================================================
function _vgRenderPhaseResults() {
  var container = document.getElementById('vg-phase-results');
  if (!container) return;

  var h = '';

  // Summary cards
  var dns = _vgState.results.dns || {};
  var subs = _vgState.results.subdomains || [];
  var hosts = _vgState.results.hosts || [];
  var alive = hosts.filter(function(ho) { return ho.alive; });
  var tech = _vgState.results.tech || [];
  var sec = _vgState.results.security || [];

  h += '<div style="padding-top:16px;">';
  h += '<div style="font-size:14px;color:#00ddff;font-weight:bold;letter-spacing:2px;margin-bottom:12px;">RECONNAISSANCE SUMMARY</div>';

  // Stats row
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-bottom:16px;">';
  var stats = [
    { label: 'DNS Records', value: Object.keys(dns).reduce(function(s, k) { return s + (dns[k] || []).length; }, 0), color: '#00aaff' },
    { label: 'Subdomains', value: subs.length, color: '#aa66ff' },
    { label: 'Live Hosts', value: alive.length, color: '#00ff88' },
    { label: 'Technologies', value: tech.reduce(function(s, t) { return s + t.technologies.length; }, 0), color: '#ffaa00' },
    { label: 'Findings', value: _vgState.findings.length, color: '#ff6600' },
    { label: 'Critical', value: _vgState.findings.filter(function(f) { return f.severity === 'critical'; }).length, color: '#ff2222' }
  ];
  stats.forEach(function(stat) {
    h += '<div style="background:' + stat.color + '08;border:1px solid ' + stat.color + '33;border-radius:4px;padding:10px;text-align:center;">';
    h += '<div style="color:' + stat.color + ';font-size:22px;font-weight:bold;">' + stat.value + '</div>';
    h += '<div style="color:#4a6a8a;font-size:8px;letter-spacing:1px;margin-top:2px;">' + stat.label.toUpperCase() + '</div>';
    h += '</div>';
  });
  h += '</div>';

  // Subdomains list
  if (subs.length > 0) {
    h += '<details style="margin-bottom:10px;">';
    h += '<summary style="color:#aa66ff;font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">DISCOVERED SUBDOMAINS (' + subs.length + ')</summary>';
    h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;max-height:200px;overflow-y:auto;margin-top:4px;">';
    subs.forEach(function(sub) {
      h += '<div style="font-size:10px;margin:1px 0;color:#8ab4d4;">' + esc(sub.name) + ' <span style="color:#3a5a7a;">(' + esc(sub.source) + ')</span></div>';
    });
    h += '</div></details>';
  }

  // Live hosts
  if (alive.length > 0) {
    h += '<details style="margin-bottom:10px;">';
    h += '<summary style="color:#00ff88;font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">LIVE HOSTS (' + alive.length + ')</summary>';
    h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;margin-top:4px;">';
    alive.forEach(function(ho) {
      h += '<div style="font-size:10px;margin:2px 0;display:flex;gap:8px;">';
      h += '<span style="color:#00ff88;min-width:200px;">' + esc(ho.host) + '</span>';
      h += '<span style="color:#4a6a8a;">' + ho.protocol.toUpperCase() + '</span>';
      h += '<span style="color:#6a8aaa;">' + ho.status + '</span>';
      h += '<span style="color:#3a5a7a;">' + ho.time + 'ms</span>';
      h += '</div>';
    });
    h += '</div></details>';
  }

  // Security grades
  if (sec.length > 0) {
    h += '<details style="margin-bottom:10px;" open>';
    h += '<summary style="color:#ffaa00;font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">SECURITY GRADES (' + sec.length + ' hosts)</summary>';
    h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;margin-top:4px;">';
    sec.forEach(function(s) {
      var gc = { A: '#00ff88', B: '#44cc44', C: '#ffaa00', D: '#ff6600', F: '#ff2222' }[s.grade] || '#4a6a8a';
      h += '<div style="display:flex;align-items:center;gap:10px;margin:4px 0;font-size:10px;">';
      h += '<span style="color:' + gc + ';font-size:18px;font-weight:bold;min-width:24px;text-align:center;">' + s.grade + '</span>';
      h += '<span style="color:#c8d6e5;flex:1;">' + esc(s.host) + '</span>';
      h += '<span style="color:#4a6a8a;">' + s.score + '%</span>';
      h += '</div>';
    });
    h += '</div></details>';
  }

  // CVE correlation
  var vulns = _vgState.results.vulns || [];
  if (vulns.length > 0) {
    h += '<details style="margin-bottom:10px;">';
    h += '<summary style="color:#ff6644;font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">CVE CORRELATION (' + vulns.length + ' vulnerabilities)</summary>';
    h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;margin-top:4px;max-height:250px;overflow-y:auto;">';
    vulns.forEach(function(v) {
      var vc = v.severity === 'critical' ? '#ff2222' : v.severity === 'high' ? '#ff6600' : v.severity === 'medium' ? '#ffaa00' : '#00cc88';
      h += '<div style="display:flex;gap:8px;margin:3px 0;font-size:10px;align-items:flex-start;">';
      h += '<span style="color:' + vc + ';font-weight:bold;min-width:120px;">' + esc(v.cve) + '</span>';
      h += '<span style="color:' + vc + ';min-width:30px;">' + v.score + '</span>';
      h += '<span style="color:#6a8aaa;min-width:80px;">' + esc(v.tech) + '</span>';
      if (v.inKEV) h += '<span style="color:#ff2222;font-size:8px;background:#ff222215;border:1px solid #ff222233;padding:0 4px;border-radius:2px;">KEV</span>';
      h += '</div>';
    });
    h += '</div></details>';
  }

  // Infrastructure
  var infra = _vgState.results.infra || [];
  if (infra.length > 0) {
    h += '<details style="margin-bottom:10px;">';
    h += '<summary style="color:#00ddff;font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">INFRASTRUCTURE (' + infra.length + ' IPs)</summary>';
    h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;margin-top:4px;">';
    infra.forEach(function(ip) {
      h += '<div style="display:flex;gap:8px;margin:3px 0;font-size:10px;">';
      h += '<span style="color:#00aaff;min-width:120px;">' + esc(ip.ip) + '</span>';
      h += '<span style="color:#6a8aaa;min-width:100px;">' + esc(ip.country || '') + '</span>';
      h += '<span style="color:#4a6a8a;">' + esc(ip.cloud || ip.org || '') + '</span>';
      if (ip.bulletproof) h += '<span style="color:#ff2222;font-size:8px;background:#ff222215;border:1px solid #ff222233;padding:0 4px;border-radius:2px;">BULLETPROOF</span>';
      h += '</div>';
    });
    h += '</div></details>';
  }

  // Email security
  var emailR = _vgState.results.email;
  if (emailR) {
    var egc = { A: '#00ff88', B: '#44cc44', C: '#ffaa00', D: '#ff6600', F: '#ff2222' }[emailR.grade] || '#4a6a8a';
    h += '<details style="margin-bottom:10px;">';
    h += '<summary style="color:' + egc + ';font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">EMAIL SECURITY — Grade: ' + emailR.grade + '</summary>';
    h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;margin-top:4px;font-size:10px;">';
    h += '<div>SPF: ' + (emailR.spf ? '<span style="color:#00ff88">' + esc(emailR.spf.substring(0, 80)) + '</span>' : '<span style="color:#ff4444">NOT FOUND</span>') + '</div>';
    h += '<div>DMARC: ' + (emailR.dmarc ? '<span style="color:#00ff88">' + esc(emailR.dmarc.substring(0, 80)) + '</span>' : '<span style="color:#ff4444">NOT FOUND</span>') + '</div>';
    h += '<div>DKIM selectors: ' + (emailR.dkim || []).length + (emailR.dkim && emailR.dkim.length > 0 ? ' (' + emailR.dkim.map(function(d) { return d.selector; }).join(', ') + ')' : '') + '</div>';
    h += '</div></details>';
  }

  // Risk score
  var scoreR = _vgState.results.score;
  if (scoreR) {
    h += '<div style="background:' + scoreR.color + '08;border:2px solid ' + scoreR.color + '44;border-radius:8px;padding:16px;margin-bottom:12px;text-align:center;">';
    h += '<div style="color:' + scoreR.color + ';font-size:48px;font-weight:bold;text-shadow:0 0 20px ' + scoreR.color + '40;">' + scoreR.score + '</div>';
    h += '<div style="color:' + scoreR.color + ';font-size:14px;letter-spacing:3px;">' + scoreR.level + '</div>';
    h += '<div style="color:#4a6a8a;font-size:9px;margin-top:4px;">ATTACK SURFACE RISK SCORE</div>';
    h += '</div>';
  }

  // Report export
  if (_vgState.results.report) {
    h += '<div style="margin-top:12px;display:flex;gap:8px;">';
    h += '<button onclick="_vgCopyReport()" style="background:#ff660015;color:#ff6600;border:1px solid #ff660033;padding:8px 16px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">COPY FULL REPORT (HTML)</button>';
    h += '<button onclick="_vgExportJSON()" style="background:#00aaff15;color:#00aaff;border:1px solid #00aaff33;padding:8px 16px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">EXPORT JSON</button>';
    h += '<button onclick="_vgExportLog()" style="background:#aa66ff15;color:#aa66ff;border:1px solid #aa66ff33;padding:8px 16px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">EXPORT LOG</button>';
    h += '</div>';
  } else {
    h += '<div style="margin-top:12px;display:flex;gap:8px;">';
    h += '<button onclick="_vgExportJSON()" style="background:#00aaff15;color:#00aaff;border:1px solid #00aaff33;padding:8px 16px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">EXPORT JSON</button>';
    h += '<button onclick="_vgExportLog()" style="background:#aa66ff15;color:#aa66ff;border:1px solid #aa66ff33;padding:8px 16px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">EXPORT LOG</button>';
    h += '</div>';
  }

  h += '</div>';

  container.innerHTML = h;
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================
window._vgExportJSON = function() {
  var data = {
    target: _vgState.target,
    scanDate: new Date().toISOString(),
    engine: 'VANGUARD v1.0',
    results: _vgState.results,
    findings: _vgState.findings,
    duration: _vgState.startTime ? ((performance.now() - _vgState.startTime) / 1000).toFixed(1) + 's' : 'N/A'
  };
  try {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    _vgLog('Results exported to clipboard as JSON', 'success');
  } catch (e) {
    _vgLog('Export failed: ' + e.message, 'error');
  }
};

window._vgExportLog = function() {
  var logText = _vgState.log.map(function(entry) {
    return '[' + _vgPadTime(entry.time) + '] ' + entry.message;
  }).join('\n');
  try {
    navigator.clipboard.writeText(logText);
    _vgLog('Operation log exported to clipboard', 'success');
  } catch (e) {
    _vgLog('Export failed: ' + e.message, 'error');
  }
};

window._vgCopyReport = function() {
  if (!_vgState.results.report) {
    _vgLog('No report available — run a complete scan first', 'error');
    return;
  }
  try {
    navigator.clipboard.writeText(_vgState.results.report);
    _vgLog('Full HTML report copied to clipboard (' + Math.round(_vgState.results.report.length / 1024) + ' KB)', 'success');
  } catch (e) {
    _vgLog('Report copy failed: ' + e.message, 'error');
  }
};
