/**
 * AuthGuardian AI — Secure Code Review Engine
 * ==============================================
 * Reviews Auth0 Actions, Rules, Hooks, and authentication-related scripts
 * for security vulnerabilities, insecure patterns, and best practice violations.
 *
 * This is FEATURE 2 — AI-Powered Auth0 Secure Code Review Bot.
 *
 * @module code-review
 */

const config = require('../../configs/review-config');

/**
 * Runs secure code review on all code files.
 *
 * @param {Array<object>} changedFiles - Output from diff-parser (filtered to code files)
 * @returns {object} { findings, reviewedFiles, stats }
 */
function runCodeReview(changedFiles) {
  const codeFiles = changedFiles.filter(f => f.isCode && f.changeType !== 'deleted');
  const findings = [];
  const reviewedFiles = [];

  for (const file of codeFiles) {
    if (!file.content) {
      reviewedFiles.push({ ...file, findings: [], skipped: true, reason: 'No content available' });
      continue;
    }

    const fileFindings = analyzeCode(file);
    findings.push(...fileFindings);
    reviewedFiles.push({ ...file, findings: fileFindings, skipped: false });
  }

  return {
    findings,
    reviewedFiles,
    stats: {
      totalCodeFiles: codeFiles.length,
      totalFindings: findings.length,
    },
  };
}

/**
 * Performs comprehensive code analysis on a single file.
 *
 * @param {object} file - File descriptor with content
 * @returns {Array<object>} Findings
 */
function analyzeCode(file) {
  const code = file.content;
  const context = `${file.resourceMeta.icon} ${file.resourceMeta.label} — \`${file.filePath}\``;
  const findings = [];

  // Run all code analysis checks
  findings.push(...checkHardcodedSecrets(code, context));
  findings.push(...checkInsecureLogging(code, context));
  findings.push(...checkInsecureRedirects(code, context));
  findings.push(...checkJwtHandling(code, context));
  findings.push(...checkErrorHandling(code, context));
  findings.push(...checkInsecureApiCalls(code, context));
  findings.push(...checkUnsafeAsyncPatterns(code, context));
  findings.push(...checkAuth0BestPractices(code, context));
  findings.push(...checkRbacLogic(code, context));
  findings.push(...checkSessionHandling(code, context));
  findings.push(...checkDataLeakage(code, context));
  findings.push(...checkInputValidation(code, context));

  // Tag all findings with file info
  return findings.map(f => ({
    ...f,
    file: file.filePath,
    resourceType: file.resourceType,
    changeType: file.changeType,
  }));
}

// ─────────────────────────────────────────────────────────────
// CHECK FUNCTIONS — Each returns an array of findings
// ─────────────────────────────────────────────────────────────

/**
 * Checks for hardcoded secrets, API keys, and credentials.
 */
function checkHardcodedSecrets(code, context) {
  return runPatternChecks(code, context, config.codeReviewRules.secretPatterns, 'Secrets & Credentials');
}

/**
 * Checks for insecure logging of sensitive data.
 */
function checkInsecureLogging(code, context) {
  return runPatternChecks(code, context, config.codeReviewRules.insecureLoggingPatterns, 'Insecure Logging');
}

/**
 * Checks for insecure redirect patterns.
 */
function checkInsecureRedirects(code, context) {
  return runPatternChecks(code, context, config.codeReviewRules.insecureRedirectPatterns, 'Insecure Redirects');
}

/**
 * Checks for insecure JWT handling.
 */
function checkJwtHandling(code, context) {
  return runPatternChecks(code, context, config.codeReviewRules.jwtPatterns, 'JWT Security');
}

/**
 * Checks for error handling issues.
 */
function checkErrorHandling(code, context) {
  const findings = [];
  const rules = config.codeReviewRules.errorHandlingPatterns;

  for (const rule of rules) {
    if (rule.id === 'NO_TRY_CATCH') {
      // Special handling: check if the file has Auth0 handler patterns without try/catch
      findings.push(...checkMissingTryCatch(code, context));
      continue;
    }
    if (rule.pattern.test(code)) {
      findings.push(createFinding(rule, context, getMatchSnippet(code, rule.pattern), 'Error Handling'));
    }
  }

  return findings;
}

/**
 * Checks for missing try/catch in Auth0 Action handlers.
 */
function checkMissingTryCatch(code, context) {
  const findings = [];

  // Detect Auth0 Action handler patterns
  const handlerPatterns = [
    /exports\.onExecutePostLogin\s*=\s*async/,
    /exports\.onContinuePostLogin\s*=\s*async/,
    /exports\.onExecutePreUserRegistration\s*=\s*async/,
    /exports\.onExecutePostUserRegistration\s*=\s*async/,
    /exports\.onExecuteCredentialsExchange\s*=\s*async/,
    /exports\.onExecutePostChangePassword\s*=\s*async/,
    /exports\.onExecuteSendPhoneMessage\s*=\s*async/,
  ];

  for (const handlerPattern of handlerPatterns) {
    const match = code.match(handlerPattern);
    if (match) {
      // Extract the function body (simple heuristic — count braces)
      const startIdx = code.indexOf(match[0]);
      const functionBody = extractFunctionBody(code, startIdx);

      if (functionBody && !functionBody.includes('try') && !functionBody.includes('catch')) {
        findings.push({
          id: 'AUTH0_NO_TRY_CATCH',
          severity: 'MEDIUM',
          category: 'Error Handling',
          title: 'Auth0 Action handler lacks try/catch',
          description: `${context}: The handler \`${match[0].split('=')[0].trim()}\` does not wrap its logic in a try/catch block.`,
          impact: 'Unhandled exceptions in Auth0 Actions cause the entire login flow to fail with a generic error, degrading user experience.',
          recommendation: 'Wrap the handler body in try/catch. In the catch block, log the error and call api.access.deny() or handle gracefully.',
          resource: context,
          evidence: match[0],
        });
      }
    }
  }

  return findings;
}

/**
 * Checks for insecure API calls.
 */
function checkInsecureApiCalls(code, context) {
  return runPatternChecks(code, context, config.codeReviewRules.insecureApiPatterns, 'Insecure API Calls');
}

/**
 * Checks for unsafe async patterns.
 */
function checkUnsafeAsyncPatterns(code, context) {
  return runPatternChecks(code, context, config.codeReviewRules.unsafeAsyncPatterns, 'Async Safety');
}

/**
 * Checks Auth0-specific best practices.
 */
function checkAuth0BestPractices(code, context) {
  const findings = [];
  const rules = config.codeReviewRules.auth0BestPractices;

  // Check positive patterns (good practices that SHOULD be present)
  for (const rule of rules) {
    if (rule.check === 'positive') {
      // These are informational — don't flag as findings unless we extend to "kudos"
      continue;
    }
    if (rule.pattern.test(code)) {
      findings.push(createFinding(rule, context, getMatchSnippet(code, rule.pattern), 'Auth0 Best Practices'));
    }
  }

  // Check for direct Management API calls instead of using event.secrets
  if (/https:\/\/.*\.auth0\.com\/api\/v2\//i.test(code) && !/event\.secrets/i.test(code)) {
    findings.push({
      id: 'AUTH0_DIRECT_API',
      severity: 'MEDIUM',
      category: 'Auth0 Best Practices',
      title: 'Direct Management API call without event.secrets',
      description: `${context}: Code makes direct Auth0 Management API calls without using event.secrets for credentials.`,
      impact: 'Hardcoded API URLs and credentials bypass Auth0 Action secret management, making rotation difficult.',
      recommendation: 'Store Auth0 domain and credentials in Action Secrets. Access via event.secrets.MY_SECRET.',
      resource: context,
      evidence: 'Direct https://*.auth0.com/api/v2/ call detected',
    });
  }

  // Check for deprecated event properties
  if (/event\.context\./i.test(code)) {
    findings.push({
      id: 'AUTH0_DEPRECATED_CONTEXT',
      severity: 'LOW',
      category: 'Auth0 Best Practices',
      title: 'Possible use of deprecated event.context',
      description: `${context}: Code references event.context which may be deprecated in newer Action versions.`,
      impact: 'Deprecated properties may be removed in future Auth0 versions.',
      recommendation: 'Use the appropriate event properties for your Action trigger type (e.g., event.request, event.user).',
      resource: context,
      evidence: 'event.context.*',
    });
  }

  return findings;
}

/**
 * Checks for RBAC logic issues.
 */
function checkRbacLogic(code, context) {
  const findings = [];

  // Check for hardcoded role names
  const roleCheckPattern = /(?:role|roles)\s*(?:===?|!==?|includes|indexOf)\s*['"`]([^'"`]+)['"`]/gi;
  let match;
  while ((match = roleCheckPattern.exec(code)) !== null) {
    findings.push({
      id: 'RBAC_HARDCODED_ROLE',
      severity: 'LOW',
      category: 'RBAC',
      title: 'Hardcoded role name in authorization logic',
      description: `${context}: Role name "${match[1]}" is hardcoded in authorization logic.`,
      impact: 'Hardcoded role names are fragile. If roles are renamed, the authorization logic silently breaks.',
      recommendation: 'Use role IDs or store role names in Action Secrets for easier management.',
      resource: context,
      evidence: match[0],
    });
  }

  // Check for missing role/permission checks before sensitive operations
  if (/api\.access\.deny/i.test(code) && !/(?:role|permission|authorization)/i.test(code)) {
    findings.push({
      id: 'RBAC_DENY_WITHOUT_CHECK',
      severity: 'LOW',
      category: 'RBAC',
      title: 'api.access.deny without clear authorization check',
      description: `${context}: Code calls api.access.deny but doesn't clearly check roles/permissions.`,
      impact: 'Unclear authorization logic is hard to audit and maintain.',
      recommendation: 'Ensure deny decisions are clearly tied to role/permission checks.',
      resource: context,
      evidence: 'api.access.deny without role/permission check',
    });
  }

  return findings;
}

/**
 * Checks for session handling issues.
 */
function checkSessionHandling(code, context) {
  const findings = [];

  // Check for session fixation risks
  if (/session\s*\[/i.test(code) && !/session\.regenerate|session\.destroy/i.test(code)) {
    findings.push({
      id: 'SESSION_NO_REGENERATION',
      severity: 'MEDIUM',
      category: 'Session Security',
      title: 'Session manipulation without regeneration',
      description: `${context}: Code modifies session data without regenerating the session ID.`,
      impact: 'Session fixation attacks may allow an attacker to hijack a user session.',
      recommendation: 'Regenerate session IDs after authentication state changes.',
      resource: context,
      evidence: 'session[...] without session.regenerate',
    });
  }

  return findings;
}

/**
 * Checks for potential data leakage.
 */
function checkDataLeakage(code, context) {
  const findings = [];

  // Check for returning sensitive user data in custom claims
  const sensitiveClaimPatterns = [
    /setCustomClaim\s*\(\s*['"`]\w*['"`]\s*,\s*event\.user\.email/i,
    /setCustomClaim\s*\(\s*['"`]\w*['"`]\s*,\s*event\.user\.phone/i,
    /setCustomClaim\s*\(\s*['"`]\w*['"`]\s*,\s*event\.user\.identities/i,
  ];

  for (const pattern of sensitiveClaimPatterns) {
    if (pattern.test(code)) {
      const matched = code.match(pattern);
      findings.push({
        id: 'DATA_SENSITIVE_CLAIM',
        severity: 'MEDIUM',
        category: 'Data Protection',
        title: 'Sensitive user data in custom token claim',
        description: `${context}: Sensitive user data is being added to token claims.`,
        impact: 'Token claims are visible to client applications. Including PII or sensitive data may violate privacy policies.',
        recommendation: 'Only include non-sensitive, necessary data in token claims. Fetch sensitive data from backend APIs instead.',
        resource: context,
        evidence: matched ? matched[0] : 'Sensitive claim pattern',
      });
    }
  }

  return findings;
}

/**
 * Checks for weak input validation.
 */
function checkInputValidation(code, context) {
  const findings = [];

  // Check for eval usage
  if (/\beval\s*\(/i.test(code)) {
    findings.push({
      id: 'INPUT_EVAL',
      severity: 'CRITICAL',
      category: 'Input Validation',
      title: 'Use of eval() detected',
      description: `${context}: Code uses eval() which executes arbitrary code.`,
      impact: 'eval() can execute injected malicious code, leading to complete compromise of the Action execution context.',
      recommendation: 'Remove eval(). Use JSON.parse() for data parsing. Refactor logic to avoid dynamic code execution.',
      resource: context,
      evidence: 'eval(...)',
    });
  }

  // Check for new Function() usage
  if (/new\s+Function\s*\(/i.test(code)) {
    findings.push({
      id: 'INPUT_NEW_FUNCTION',
      severity: 'HIGH',
      category: 'Input Validation',
      title: 'Dynamic function construction detected',
      description: `${context}: Code uses new Function() which is similar to eval().`,
      impact: 'new Function() creates code from strings, enabling code injection attacks.',
      recommendation: 'Remove new Function(). Use static function definitions instead.',
      resource: context,
      evidence: 'new Function(...)',
    });
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────

/**
 * Runs an array of pattern-based rules against code.
 */
function runPatternChecks(code, context, rules, category) {
  const findings = [];
  for (const rule of rules) {
    if (rule.check === 'positive') continue; // Skip positive-check rules
    if (rule.pattern.test(code)) {
      findings.push(createFinding(rule, context, getMatchSnippet(code, rule.pattern), category));
    }
  }
  return findings;
}

/**
 * Creates a standardized finding object from a rule match.
 */
function createFinding(rule, context, evidence, category) {
  return {
    id: rule.id,
    severity: rule.severity,
    category: category,
    title: rule.label,
    description: `${context}: ${rule.label}`,
    impact: getImpactText(rule.id, category),
    recommendation: getRecommendationText(rule.id, category),
    resource: context,
    evidence: evidence || rule.label,
  };
}

/**
 * Extracts a code snippet around a regex match for evidence.
 */
function getMatchSnippet(code, pattern) {
  const match = code.match(pattern);
  if (!match) return 'Pattern matched';
  const idx = match.index || 0;
  const start = Math.max(0, idx - 30);
  const end = Math.min(code.length, idx + match[0].length + 30);
  return code.substring(start, end).replace(/\n/g, ' ').trim();
}

/**
 * Extracts the body of a function starting at the given index.
 */
function extractFunctionBody(code, startIdx) {
  let braceCount = 0;
  let foundOpen = false;
  let bodyStart = -1;

  for (let i = startIdx; i < code.length && i < startIdx + 5000; i++) {
    if (code[i] === '{') {
      if (!foundOpen) bodyStart = i;
      foundOpen = true;
      braceCount++;
    } else if (code[i] === '}') {
      braceCount--;
      if (foundOpen && braceCount === 0) {
        return code.substring(bodyStart, i + 1);
      }
    }
  }
  return null;
}

/**
 * AI-style impact text generation based on finding ID and category.
 */
function getImpactText(ruleId, category) {
  const impacts = {
    // Secrets
    SECRET_HARDCODED: 'Hardcoded secrets in source code can be extracted by anyone with repository access. If the secret is for a production service, this constitutes a critical data breach risk.',
    SECRET_INLINE: 'Inline secrets are committed to version control history permanently. Even after removal, they remain in git history.',
    SECRET_PRIVATE_KEY: 'Private keys embedded in code enable impersonation, decryption of sensitive data, and signing of forged tokens.',
    SECRET_GITHUB_TOKEN: 'GitHub tokens provide access to repositories, actions, and potentially deployment pipelines.',
    // Logging
    LOG_SENSITIVE: 'Logging sensitive data may expose credentials or PII in log aggregation systems, violating security and privacy policies.',
    LOG_AUTH0_OBJECTS: 'Auth0 event/context objects may contain user PII, tokens, or internal data that should not appear in logs.',
    // JWT
    JWT_NONE_ALG: 'The "none" algorithm allows attackers to forge tokens that bypass signature verification entirely.',
    JWT_VERIFY_DISABLED: 'Disabling JWT verification accepts any token, including forged or expired ones.',
    JWT_IGNORE_EXPIRY: 'Ignoring token expiration allows use of old, potentially compromised tokens.',
    // API
    API_HTTP: 'Non-HTTPS API calls transmit data (including tokens and secrets) in plaintext.',
    API_TLS_DISABLED: 'Disabling TLS verification allows man-in-the-middle attacks on API connections.',
    API_HTTP_AXIOS: 'Non-HTTPS Axios requests transmit sensitive data without encryption.',
    // Async
    ASYNC_SETTIMEOUT_ZERO: 'setTimeout(fn, 0) in Auth0 Actions is unreliable as the execution context may terminate before the callback runs.',
    ASYNC_SETINTERVAL: 'setInterval cannot maintain state between Auth0 Action executions. The interval will be lost.',
    ASYNC_PROCESS_EXIT: 'process.exit() terminates the Action runtime abnormally, causing authentication failures for all users.',
  };

  return impacts[ruleId] || `This ${category} finding may introduce security vulnerabilities in the Auth0 authentication pipeline.`;
}

/**
 * AI-style recommendation text generation.
 */
function getRecommendationText(ruleId, category) {
  const recommendations = {
    SECRET_HARDCODED: 'Move secrets to Auth0 Action Secrets (event.secrets.MY_SECRET). Rotate any exposed credentials immediately.',
    SECRET_INLINE: 'Remove inline secrets. Use Auth0 Action Secrets for all sensitive values. Rotate compromised credentials.',
    SECRET_PRIVATE_KEY: 'Remove the private key from code. Store it in Auth0 Action Secrets or an external vault.',
    SECRET_GITHUB_TOKEN: 'Remove the GitHub token. Use OAuth app integration or GitHub App tokens with minimal scopes.',
    LOG_SENSITIVE: 'Remove sensitive data from log statements. Log only non-sensitive identifiers (e.g., user ID, timestamps).',
    LOG_AUTH0_OBJECTS: 'Filter Auth0 objects before logging. Extract only necessary fields: event.user.user_id, event.request.ip.',
    JWT_NONE_ALG: 'Remove "none" from allowed algorithms. Use RS256 or ES256 for token verification.',
    JWT_VERIFY_DISABLED: 'Enable JWT verification. Always validate token signatures, issuer, audience, and expiration.',
    JWT_IGNORE_EXPIRY: 'Enable expiration checking. Short-lived tokens with refresh token rotation is the recommended pattern.',
    API_HTTP: 'Use HTTPS for all API calls. Ensure TLS 1.2+ is enforced on all endpoints.',
    API_TLS_DISABLED: 'Remove rejectUnauthorized: false. Install proper CA certificates if needed.',
    API_HTTP_AXIOS: 'Change Axios base URL to HTTPS. Configure axios defaults to reject non-TLS connections.',
    ASYNC_SETTIMEOUT_ZERO: 'Remove setTimeout. Use async/await for asynchronous operations in Auth0 Actions.',
    ASYNC_SETINTERVAL: 'Remove setInterval. Auth0 Actions are stateless — use external schedulers for recurring tasks.',
    ASYNC_PROCESS_EXIT: 'Remove process.exit(). Use api.access.deny() to reject authentication, or return normally to allow.',
  };

  return recommendations[ruleId] || `Review and remediate this ${category} finding following Auth0 security best practices.`;
}

module.exports = {
  runCodeReview,
  analyzeCode,
};
