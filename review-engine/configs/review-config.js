/**
 * AuthGuardian AI — Configuration
 * ================================
 * Central configuration for security rules, severity thresholds,
 * and review engine behavior.
 *
 * This configuration is designed to be extensible. Future integrations
 * (OpenAI, LangChain, vector DBs) can add their config sections here.
 */

module.exports = {
  /**
   * Review engine metadata
   */
  meta: {
    name: 'AuthGuardian AI',
    version: '1.0.0',
    description: 'AI-Assisted IAM Governance & Secure Deployment Review Platform',
  },

  /**
   * Diff parser settings
   */
  diffParser: {
    /** Base branch to diff against (overridden by CI environment) */
    baseBranch: 'origin/main',
    /** Paths considered Auth0 configuration */
    auth0Paths: ['auth0/', 'auth0/exported/'],
    /** File extensions to analyze */
    analyzableExtensions: ['.yaml', '.yml', '.json', '.js', '.ts'],
  },

  /**
   * Auth0 resource types for classification
   */
  resourceTypes: {
    actions:          { label: 'Actions',           risk: 'HIGH',     icon: '⚡' },
    rules:            { label: 'Rules',             risk: 'HIGH',     icon: '📏' },
    hooks:            { label: 'Hooks',             risk: 'HIGH',     icon: '🪝' },
    clients:          { label: 'Applications',      risk: 'HIGH',     icon: '📱' },
    connections:      { label: 'Connections',       risk: 'HIGH',     icon: '🔗' },
    databases:        { label: 'Database Connections', risk: 'MEDIUM', icon: '🗄️' },
    resourceServers:  { label: 'APIs / Resource Servers', risk: 'MEDIUM', icon: '🌐' },
    clientGrants:     { label: 'Client Grants',     risk: 'HIGH',     icon: '🔑' },
    roles:            { label: 'Roles',             risk: 'MEDIUM',   icon: '👤' },
    prompts:          { label: 'Prompts',           risk: 'LOW',      icon: '💬' },
    branding:         { label: 'Branding',          risk: 'LOW',      icon: '🎨' },
    emailTemplates:   { label: 'Email Templates',   risk: 'LOW',      icon: '📧' },
    pages:            { label: 'Pages',             risk: 'MEDIUM',   icon: '📄' },
    tenant:           { label: 'Tenant Settings',   risk: 'HIGH',     icon: '🏢' },
    guardian:         { label: 'Guardian / MFA',     risk: 'CRITICAL', icon: '🛡️' },
    triggers:         { label: 'Triggers',          risk: 'HIGH',     icon: '🔫' },
    attackProtection: { label: 'Attack Protection', risk: 'CRITICAL', icon: '🛡️' },
    organizations:    { label: 'Organizations',     risk: 'MEDIUM',   icon: '🏛️' },
    customDomains:    { label: 'Custom Domains',    risk: 'MEDIUM',   icon: '🌍' },
    themes:           { label: 'Themes',            risk: 'LOW',      icon: '🎭' },
  },

  /**
   * Severity levels and scoring
   */
  severity: {
    levels: {
      CRITICAL: { weight: 10, color: '🔴', label: 'CRITICAL', threshold: 1 },
      HIGH:     { weight: 7,  color: '🟠', label: 'HIGH',     threshold: 3 },
      MEDIUM:   { weight: 4,  color: '🟡', label: 'MEDIUM',   threshold: 5 },
      LOW:      { weight: 1,  color: '🔵', label: 'LOW',      threshold: 10 },
    },
    /** Maximum risk score before blocking deployment (0 = never block) */
    blockingThreshold: 0,
    /** Maximum risk score before requiring approval */
    approvalThreshold: 50,
  },

  /**
   * Deployment review — IAM security rules
   */
  deploymentRules: {
    /** Callback URL patterns that are risky */
    riskyCallbackPatterns: [
      { pattern: /localhost/i,        severity: 'HIGH',     id: 'CALLBACK_LOCALHOST',     label: 'Localhost callback URL' },
      { pattern: /127\.0\.0\.1/i,     severity: 'HIGH',     id: 'CALLBACK_LOOPBACK',      label: 'Loopback callback URL' },
      { pattern: /\*/,               severity: 'CRITICAL', id: 'CALLBACK_WILDCARD',      label: 'Wildcard callback URL' },
      { pattern: /http:\/\//i,       severity: 'HIGH',     id: 'CALLBACK_HTTP',          label: 'Non-HTTPS callback URL' },
      { pattern: /\.ngrok\./i,       severity: 'HIGH',     id: 'CALLBACK_NGROK',         label: 'ngrok tunnel callback URL' },
      { pattern: /\.local(:\d+)?$/i, severity: 'MEDIUM',   id: 'CALLBACK_LOCAL_DOMAIN',  label: '.local domain callback URL' },
    ],

    /** Dangerous OAuth grant types */
    dangerousGrantTypes: [
      { grant: 'password',                        severity: 'HIGH',     id: 'GRANT_PASSWORD',   label: 'Resource Owner Password grant' },
      { grant: 'http://auth0.com/oauth/grant-type/password-realm', severity: 'HIGH', id: 'GRANT_PASSWORD_REALM', label: 'Password Realm grant' },
      { grant: 'urn:ietf:params:oauth:grant-type:device_code',    severity: 'MEDIUM', id: 'GRANT_DEVICE_CODE',  label: 'Device Code grant (verify intended)' },
    ],

    /** Token expiry thresholds (in seconds) */
    tokenExpiry: {
      accessTokenWarnMin: 300,           // 5 minutes — too short
      accessTokenWarnMax: 86400,         // 24 hours — too long
      refreshTokenWarnMax: 2592000,      // 30 days
      idTokenWarnMax: 36000,             // 10 hours
    },

    /** CORS origin patterns that are risky */
    riskyCorsPatterns: [
      { pattern: /\*/,               severity: 'CRITICAL', id: 'CORS_WILDCARD',      label: 'Wildcard CORS origin' },
      { pattern: /localhost/i,        severity: 'MEDIUM',   id: 'CORS_LOCALHOST',     label: 'Localhost CORS origin' },
      { pattern: /http:\/\//i,       severity: 'MEDIUM',   id: 'CORS_HTTP',          label: 'Non-HTTPS CORS origin' },
    ],
  },

  /**
   * Code review — Secure code analysis rules
   */
  codeReviewRules: {
    /** Patterns indicating hardcoded secrets */
    secretPatterns: [
      { pattern: /(['"`])(?:sk_live|pk_live|api[_-]?key|secret|password|token|bearer)\1\s*[:=]/i, severity: 'CRITICAL', id: 'SECRET_HARDCODED',     label: 'Potential hardcoded secret/API key' },
      { pattern: /(?:password|secret|token|key)\s*[:=]\s*['"`][^'"`]{8,}/i,                       severity: 'CRITICAL', id: 'SECRET_INLINE',       label: 'Inline secret value detected' },
      { pattern: /-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----/i,                                     severity: 'CRITICAL', id: 'SECRET_PRIVATE_KEY',  label: 'Embedded private key' },
      { pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,                                   severity: 'CRITICAL', id: 'SECRET_GITHUB_TOKEN', label: 'GitHub token detected' },
    ],

    /** Insecure logging patterns */
    insecureLoggingPatterns: [
      { pattern: /console\.\w+\(.*(?:password|secret|token|key|credential|auth)/i,  severity: 'HIGH',   id: 'LOG_SENSITIVE',     label: 'Logging potentially sensitive data' },
      { pattern: /console\.\w+\(.*(?:event|context|api)\b/i,                        severity: 'MEDIUM', id: 'LOG_AUTH0_OBJECTS', label: 'Logging Auth0 event/context objects (may contain PII)' },
    ],

    /** Insecure redirect patterns */
    insecureRedirectPatterns: [
      { pattern: /(?:redirect|location)\s*[:=]\s*(?:event|req|request)\./i,    severity: 'HIGH', id: 'REDIRECT_USER_INPUT', label: 'Redirect URL from user input (open redirect risk)' },
      { pattern: /protocol\s*[:=]\s*['"`]http['"`]/i,                          severity: 'MEDIUM', id: 'REDIRECT_HTTP',     label: 'Non-HTTPS redirect' },
    ],

    /** JWT handling issues */
    jwtPatterns: [
      { pattern: /algorithms\s*:\s*\[.*['"`]none['"`]/i,  severity: 'CRITICAL', id: 'JWT_NONE_ALG',       label: 'JWT "none" algorithm allowed' },
      { pattern: /verify\s*[:=]\s*false/i,                 severity: 'CRITICAL', id: 'JWT_VERIFY_DISABLED', label: 'JWT verification disabled' },
      { pattern: /ignoreExpiration\s*[:=]\s*true/i,        severity: 'HIGH',     id: 'JWT_IGNORE_EXPIRY',   label: 'JWT expiration check disabled' },
    ],

    /** Error handling issues */
    errorHandlingPatterns: [
      { pattern: /(?:async\s+)?(?:function|=>)[\s\S]{0,500}(?:api\.|event\.)[\s\S]{0,500}(?!try)/s, severity: 'MEDIUM', id: 'NO_TRY_CATCH', label: 'Auth0 handler may lack try/catch' },
      { pattern: /\.catch\s*\(\s*\)/,                                                                severity: 'MEDIUM', id: 'EMPTY_CATCH',  label: 'Empty catch handler (swallowed error)' },
      { pattern: /new\s+Promise\s*\((?:(?!\.catch|try|catch).)*\)/s,                                 severity: 'MEDIUM', id: 'UNHANDLED_PROMISE', label: 'Promise without error handling' },
    ],

    /** Insecure API call patterns */
    insecureApiPatterns: [
      { pattern: /fetch\s*\(\s*['"`]http:\/\//i,     severity: 'HIGH',   id: 'API_HTTP',           label: 'Non-HTTPS API call' },
      { pattern: /rejectUnauthorized\s*:\s*false/i,   severity: 'CRITICAL', id: 'API_TLS_DISABLED', label: 'TLS certificate verification disabled' },
      { pattern: /axios\.?\w*\(.*http:\/\//i,         severity: 'HIGH',   id: 'API_HTTP_AXIOS',     label: 'Non-HTTPS Axios request' },
    ],

    /** Auth0 best practices */
    auth0BestPractices: [
      { pattern: /event\.secrets\.\w+/,  check: 'positive', severity: 'INFO',   id: 'AUTH0_SECRETS_USED',  label: 'Auth0 Action secrets properly used' },
      { pattern: /api\.access\.deny/,    check: 'positive', severity: 'INFO',   id: 'AUTH0_ACCESS_DENY',   label: 'Proper access denial pattern' },
      { pattern: /api\.idToken\.setCustomClaim/, check: 'positive', severity: 'INFO', id: 'AUTH0_CUSTOM_CLAIMS', label: 'Custom token claims being set' },
      { pattern: /api\.multifactor\.enable/,     check: 'positive', severity: 'INFO', id: 'AUTH0_MFA_ENABLED',   label: 'MFA enforcement detected' },
    ],

    /** Unsafe async patterns */
    unsafeAsyncPatterns: [
      { pattern: /setTimeout\s*\(.*,\s*0\s*\)/,           severity: 'MEDIUM', id: 'ASYNC_SETTIMEOUT_ZERO', label: 'setTimeout(fn, 0) in Auth0 Action (unreliable)' },
      { pattern: /setInterval\s*\(/,                       severity: 'HIGH',   id: 'ASYNC_SETINTERVAL',     label: 'setInterval in Auth0 Action (will not persist)' },
      { pattern: /(?:process\.exit|process\.kill)\s*\(/,   severity: 'CRITICAL', id: 'ASYNC_PROCESS_EXIT',  label: 'process.exit/kill in Auth0 Action' },
    ],
  },

  /**
   * Reporting settings
   */
  reporting: {
    /** Output directory for markdown reports */
    outputDir: 'reports',
    /** Deployment review report filename */
    deploymentReportFile: 'deployment-review.md',
    /** Code review report filename */
    codeReviewReportFile: 'ai-review-report.md',
    /** Combined summary report filename */
    summaryReportFile: 'authguardian-summary.md',
  },

  /**
   * GitHub integration
   */
  github: {
    /** Enable PR comments */
    enablePrComments: true,
    /** Enable GitHub Actions job summary */
    enableJobSummary: true,
    /** Comment header for identification */
    commentHeader: '<!-- authguardian-ai-review -->',
    /** Maximum comment body size (GitHub limit is 65536) */
    maxCommentSize: 60000,
  },

  /**
   * Enterprise / compliance features
   */
  enterprise: {
    /** Enable compliance scoring */
    complianceScoring: true,
    /** Enable audit logging */
    auditLogging: true,
    /** Enable deployment approval gates */
    approvalGates: false,
    /** Enable trend analysis */
    trendAnalysis: false,
    /** Policy-as-code integration */
    policyAsCode: false,
  },

  /**
   * Future AI integration placeholders
   */
  aiIntegration: {
    /** Provider: 'rule-engine' | 'openai' | 'langchain' | 'custom' */
    provider: 'rule-engine',
    /** OpenAI config (future) */
    openai: { model: null, apiKey: null },
    /** LangChain config (future) */
    langchain: { enabled: false },
    /** Vector DB config (future) */
    vectorDb: { enabled: false, provider: null },
  },
};
