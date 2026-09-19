/**
 * DARKNODE — Attack Surface Intelligence Database
 * Reference data for VANGUARD attack surface analysis
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 */

export const COMMON_SUBDOMAINS = [
  'www','mail','ftp','admin','api','dev','staging','test','beta','vpn','remote',
  'portal','app','cdn','media','static','blog','shop','store','support','help',
  'docs','wiki','git','ci','jenkins','grafana','prometheus','kibana','elastic',
  'redis','mongo','mysql','postgres','db','database','backup','old','new','legacy',
  'archive','assets','files','upload','download','img','images','video','auth',
  'login','sso','id','oauth','accounts','billing','pay','checkout','cart','order',
  'crm','erp','hr','internal','intranet','extranet','corp','office','teams',
  'meet','chat','jira','confluence','bitbucket','gitlab','github','aws','cloud',
  'gcp','azure','s3','storage','lambda','api-v1','api-v2','graphql','ws','socket',
  'stream','feed','rss','status','health','monitor','metrics','analytics','tracking',
  'mx','smtp','pop','imap','webmail','autodiscover','exchange','owa',
  'ns1','ns2','dns1','dns2','vpn1','vpn2','gw','gateway','proxy','cache','waf',
  'edge','lb','node1','node2','worker','sandbox','demo','preview','uat','qa',
  'release','prod','web1','web2','web3','app1','app2','api1','api2','m','mobile',
  'forum','community','dev1','dev2','staging1','staging2','preprod','stg','prd',
  'console','dashboard','panel','control','manage','manager','backend','frontend',
  'origin','direct','www2','www3','mail2','smtp2','webdisk','cpanel','whm','plesk',
  'phpmyadmin','adminer','pgadmin','kibana2','es','elasticsearch','logstash',
  'vault','consul','nomad','terraform','k8s','kubernetes','docker','registry',
  'nexus','artifactory','sonar','sonarqube','sentry','newrelic','datadog',
  'pagerduty','opsgenie','statuspage','uptimerobot','pingdom','nagios','zabbix',
  'icinga','cacti','mrtg','ntp','ldap','radius','kerberos','ad','dc','dns',
  'dhcp','tftp','nfs','smb','cifs','sharepoint','onedrive','teams2'
];

export const BULLETPROOF_ASNS = [
  { asn: 48693, name: 'MAROSNET', country: 'RU', risk: 'critical' },
  { asn: 200019, name: 'ALEXHOST', country: 'MD', risk: 'critical' },
  { asn: 57043, name: 'HOSTWINDS', country: 'US', risk: 'high' },
  { asn: 51159, name: 'MVPS LTD', country: 'BG', risk: 'critical' },
  { asn: 210558, name: 'MVPS-NEW', country: 'BG', risk: 'critical' },
  { asn: 204957, name: 'GREENFLOIDNET', country: 'NL', risk: 'high' },
  { asn: 210644, name: 'AEZA GROUP', country: 'RU', risk: 'critical' },
  { asn: 44477, name: 'STARK INDUSTRIES', country: 'MD', risk: 'critical' },
  { asn: 16276, name: 'OVH', country: 'FR', risk: 'medium' },
  { asn: 14061, name: 'DIGITALOCEAN', country: 'US', risk: 'medium' },
  { asn: 209588, name: 'FLYSERVERS', country: 'NL', risk: 'high' },
  { asn: 53667, name: 'FRANTECH / BUYVM', country: 'US', risk: 'high' },
  { asn: 62904, name: 'EONIX', country: 'US', risk: 'high' },
  { asn: 174, name: 'COGENT', country: 'US', risk: 'low' },
  { asn: 9009, name: 'M247', country: 'RO', risk: 'high' },
  { asn: 49505, name: 'SELECTEL', country: 'RU', risk: 'high' },
  { asn: 59642, name: 'CHERRYSERVERS', country: 'LT', risk: 'medium' },
  { asn: 203953, name: 'PPTECHNOLOGY', country: 'GB', risk: 'high' },
  { asn: 50673, name: 'SERVERIUS', country: 'NL', risk: 'high' },
  { asn: 24940, name: 'HETZNER', country: 'DE', risk: 'medium' }
];

export const TECH_SIGNATURES = [
  { name: 'Nginx', header: 'server', pattern: /nginx/i, category: 'web-server', color: '#00aa44' },
  { name: 'Apache', header: 'server', pattern: /apache/i, category: 'web-server', color: '#cc2222' },
  { name: 'IIS', header: 'server', pattern: /microsoft-iis/i, category: 'web-server', color: '#0078d4' },
  { name: 'LiteSpeed', header: 'server', pattern: /litespeed/i, category: 'web-server', color: '#3a8dde' },
  { name: 'Caddy', header: 'server', pattern: /caddy/i, category: 'web-server', color: '#00d4aa' },
  { name: 'Cloudflare', header: 'server', pattern: /cloudflare/i, category: 'cdn-waf', color: '#f48120' },
  { name: 'Cloudflare (CF-Ray)', header: 'cf-ray', pattern: /.+/, category: 'cdn-waf', color: '#f48120' },
  { name: 'AWS CloudFront', header: 'x-amz-cf-id', pattern: /.+/, category: 'cdn', color: '#ff9900' },
  { name: 'AWS (x-amz)', header: 'x-amz-request-id', pattern: /.+/, category: 'cloud', color: '#ff9900' },
  { name: 'Akamai', header: 'x-akamai-transformed', pattern: /.+/, category: 'cdn', color: '#009bdb' },
  { name: 'Fastly', header: 'x-served-by', pattern: /cache-/i, category: 'cdn', color: '#ff282d' },
  { name: 'Varnish', header: 'x-varnish', pattern: /.+/, category: 'cache', color: '#00bcd4' },
  { name: 'PHP', header: 'x-powered-by', pattern: /php/i, category: 'language', color: '#777bb3' },
  { name: 'ASP.NET', header: 'x-powered-by', pattern: /asp\.net/i, category: 'framework', color: '#512bd4' },
  { name: 'Express', header: 'x-powered-by', pattern: /express/i, category: 'framework', color: '#333333' },
  { name: 'Next.js', header: 'x-nextjs-cache', pattern: /.+/, category: 'framework', color: '#000000' },
  { name: 'WordPress', header: 'link', pattern: /wp-json/i, category: 'cms', color: '#21759b' },
  { name: 'Shopify', header: 'x-shopid', pattern: /.+/, category: 'cms', color: '#96bf48' },
  { name: 'Firebase', header: 'x-cloud-trace-context', pattern: /.+/, category: 'platform', color: '#ffca28' },
  { name: 'Vercel', header: 'x-vercel-id', pattern: /.+/, category: 'platform', color: '#000000' },
  { name: 'Netlify', header: 'x-nf-request-id', pattern: /.+/, category: 'platform', color: '#00c7b7' },
  { name: 'Heroku', header: 'via', pattern: /vegur/i, category: 'platform', color: '#430098' },
  { name: 'Google Cloud', header: 'server', pattern: /Google Frontend/i, category: 'cloud', color: '#4285f4' },
  { name: 'Azure', header: 'x-azure-ref', pattern: /.+/, category: 'cloud', color: '#0078d4' }
];

export const SECURITY_HEADERS_REFERENCE = [
  { header: 'Content-Security-Policy', importance: 'critical', description: 'Controls which resources the browser can load. Prevents XSS, clickjacking, and data injection.', remediation: "Add CSP header with strict policy. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" },
  { header: 'Strict-Transport-Security', importance: 'critical', description: 'Forces HTTPS connections. Prevents SSL stripping and downgrade attacks.', remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' },
  { header: 'X-Frame-Options', importance: 'high', description: 'Prevents clickjacking by controlling iframe embedding.', remediation: 'Add: X-Frame-Options: DENY (or SAMEORIGIN if iframes needed)' },
  { header: 'X-Content-Type-Options', importance: 'high', description: 'Prevents MIME type sniffing, reducing XSS risk.', remediation: 'Add: X-Content-Type-Options: nosniff' },
  { header: 'Referrer-Policy', importance: 'medium', description: 'Controls how much referrer info is sent with requests.', remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin' },
  { header: 'Permissions-Policy', importance: 'medium', description: 'Controls which browser features the page can use (camera, microphone, geolocation).', remediation: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()' },
  { header: 'Cross-Origin-Opener-Policy', importance: 'medium', description: 'Isolates browsing context to prevent Spectre-type attacks.', remediation: 'Add: Cross-Origin-Opener-Policy: same-origin' },
  { header: 'Cross-Origin-Resource-Policy', importance: 'medium', description: 'Prevents other sites from reading responses.', remediation: 'Add: Cross-Origin-Resource-Policy: same-origin' },
  { header: 'X-XSS-Protection', importance: 'low', description: 'Legacy XSS filter. Modern CSP is preferred but this adds defense in depth.', remediation: 'Add: X-XSS-Protection: 1; mode=block (or 0 if CSP is strong)' },
  { header: 'X-DNS-Prefetch-Control', importance: 'low', description: 'Controls DNS prefetching which can leak information.', remediation: 'Add: X-DNS-Prefetch-Control: off' }
];

export const MITRE_RECON_TECHNIQUES = [
  { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance', description: 'Adversaries may execute active reconnaissance scans to gather information for targeting.', subtechniques: ['T1595.001 Scanning IP Blocks', 'T1595.002 Vulnerability Scanning', 'T1595.003 Wordlist Scanning'] },
  { id: 'T1590', name: 'Gather Victim Network Information', tactic: 'Reconnaissance', description: 'Adversaries may gather information about the victim network.', subtechniques: ['T1590.001 Domain Properties', 'T1590.002 DNS', 'T1590.003 Network Trust Dependencies', 'T1590.004 Network Topology', 'T1590.005 IP Addresses', 'T1590.006 Network Security Appliances'] },
  { id: 'T1592', name: 'Gather Victim Host Information', tactic: 'Reconnaissance', description: 'Adversaries may gather information about the victim hosts.', subtechniques: ['T1592.001 Hardware', 'T1592.002 Software', 'T1592.003 Firmware', 'T1592.004 Client Configurations'] },
  { id: 'T1589', name: 'Gather Victim Identity Information', tactic: 'Reconnaissance', description: 'Adversaries may gather information about the victim identity.', subtechniques: ['T1589.001 Credentials', 'T1589.002 Email Addresses', 'T1589.003 Employee Names'] },
  { id: 'T1591', name: 'Gather Victim Org Information', tactic: 'Reconnaissance', description: 'Adversaries may gather information about the victim organization.', subtechniques: ['T1591.001 Determine Physical Locations', 'T1591.002 Business Relationships', 'T1591.003 Identify Business Tempo', 'T1591.004 Identify Roles'] },
  { id: 'T1596', name: 'Search Open Technical Databases', tactic: 'Reconnaissance', description: 'Adversaries may search freely available technical databases for information.', subtechniques: ['T1596.001 DNS/Passive DNS', 'T1596.002 WHOIS', 'T1596.003 Digital Certificates', 'T1596.004 CDNs', 'T1596.005 Scan Databases'] },
  { id: 'T1593', name: 'Search Open Websites/Domains', tactic: 'Reconnaissance', description: 'Adversaries may search freely available websites and/or domains.', subtechniques: ['T1593.001 Social Media', 'T1593.002 Search Engines', 'T1593.003 Code Repositories'] },
  { id: 'T1594', name: 'Search Victim-Owned Websites', tactic: 'Reconnaissance', description: 'Adversaries may search websites owned by the victim for information.' },
  { id: 'T1597', name: 'Search Closed Sources', tactic: 'Reconnaissance', description: 'Adversaries may search and gather information about victims from closed sources.', subtechniques: ['T1597.001 Threat Intel Vendors', 'T1597.002 Purchase Technical Data'] },
  { id: 'T1598', name: 'Phishing for Information', tactic: 'Reconnaissance', description: 'Adversaries may send phishing messages to elicit sensitive information.', subtechniques: ['T1598.001 Spearphishing Service', 'T1598.002 Spearphishing Attachment', 'T1598.003 Spearphishing Link'] }
];

export const DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3',
  'mandrill', 'amazonses', 'sendgrid', 's1', 's2', 'dkim', 'mail',
  'email', 'smtp', 'mta', 'protonmail', 'zoho', 'mailchimp', 'cm',
  'pm', 'turbo-smtp', 'sparkpost', 'mailgun', 'postmark', 'ses',
  'everlytickey1', 'everlytickey2', 'mimecast20190104', 'sig1'
];
