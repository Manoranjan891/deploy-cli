/**
 * AuthGuardian AI — Validators
 * ==============================
 * Reusable validation functions for Auth0 configuration security analysis.
 * Each validator returns an array of findings.
 *
 * @module validators
 */

const config = require('../../configs/review-config');

// ─────────────────────────────────────────────────────────────
// CALLBACK / REDIRECT URL VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates callback URLs for security risks.
 *
 * @param {string[]} urls - Array of callback/redirect URLs
 * @param {string} context - Context description (e.g., "Application 'MyApp'")
 * @param {string} fieldName - Field name (e.g., "callbacks", "allowed_logout_urls")
 * @returns {Array<object>} Findings
 */
function validateCallbackUrls(urls, context, fieldName = 'callbacks') {
  const findings = [];
  if (!Array.isArray(urls)) return findings;

  for (const url of urls) {
    if (typeof url !== 'string') continue;
    for (const rule of config.deploymentRules.riskyCallbackPatterns) {
      if (rule.pattern.test(url)) {
        findings.push({
          id: rule.id,
          severity: rule.severity,
          category: 'IAM Security',
          title: `${rule.label} in ${fieldName}`,
          description: `${context} contains a risky ${fieldName} URL: \`${url}\``,
          impact: getCallbackImpact(rule.id),
          recommendation: getCallbackRecommendation(rule.id),
          resource: context,
          evidence: url,
        });
      }
    }
  }

  return findings;
}

/**
 * Returns impact description for callback URL findings.
 */
function getCallbackImpact(ruleId) {
  const impacts = {
    CALLBACK_WILDCARD: 'Wildcard callback URLs allow attackers to redirect authentication responses to any domain, enabling token theft and account takeover.',
    CALLBACK_LOCALHOST: 'Localhost URLs in production indicate development configuration leak. May expose tokens to local services.',
    CALLBACK_LOOPBACK: 'Loopback addresses should not be present in production configurations.',
    CALLBACK_HTTP: 'Non-HTTPS callback URLs transmit tokens in plaintext, vulnerable to man-in-the-middle attacks.',
    CALLBACK_NGROK: 'ngrok tunnel URLs expose authentication flows to temporary public endpoints. Not suitable for production.',
    CALLBACK_LOCAL_DOMAIN: '.local domains indicate development/internal configuration that should not be in production.',
  };
  return impacts[ruleId] || 'May introduce security vulnerabilities in the authentication flow.';
}

/**
 * Returns recommendation for callback URL findings.
 */
function getCallbackRecommendation(ruleId) {
  const recommendations = {
    CALLBACK_WILDCARD: 'Remove wildcard entries. Restrict callback URLs to specific, approved enterprise domains only.',
    CALLBACK_LOCALHOST: 'Remove localhost URLs from production configuration. Use environment-specific configurations.',
    CALLBACK_LOOPBACK: 'Remove 127.0.0.1 references. Use proper domain names for each environment.',
    CALLBACK_HTTP: 'Use HTTPS for all callback URLs. Configure TLS certificates for all redirect endpoints.',
    CALLBACK_NGROK: 'Remove ngrok URLs. Use stable, SSL-secured endpoints for authentication callbacks.',
    CALLBACK_LOCAL_DOMAIN: 'Replace .local domains with proper DNS entries for the target environment.',
  };
  return recommendations[ruleId] || 'Review and restrict URLs to approved domains only.';
}

// ─────────────────────────────────────────────────────────────
// GRANT TYPE VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates OAuth grant types for security risks.
 *
 * @param {string[]} grantTypes - Array of grant type strings
 * @param {string} context - Context description
 * @returns {Array<object>} Findings
 */
function validateGrantTypes(grantTypes, context) {
  const findings = [];
  if (!Array.isArray(grantTypes)) return findings;

  for (const grant of grantTypes) {
    for (const rule of config.deploymentRules.dangerousGrantTypes) {
      if (grant === rule.grant) {
        findings.push({
          id: rule.id,
          severity: rule.severity,
          category: 'IAM Security',
          title: `${rule.label} enabled`,
          description: `${context} has the "${grant}" grant type enabled.`,
          impact: `The ${rule.label} is considered insecure for modern applications. It exposes user credentials to the client application directly.`,
          recommendation: 'Use Authorization Code flow with PKCE for SPAs/mobile apps, or Client Credentials for M2M. Remove legacy password-based grants.',
          resource: context,
          evidence: grant,
        });
      }
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// TOKEN EXPIRY VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates token expiry settings.
 *
 * @param {object} tokenConfig - Token configuration object
 * @param {string} context - Context description
 * @returns {Array<object>} Findings
 */
function validateTokenExpiry(tokenConfig, context) {
  const findings = [];
  if (!tokenConfig || typeof tokenConfig !== 'object') return findings;

  const rules = config.deploymentRules.tokenExpiry;

  // Access token lifetime
  const accessTokenLifetime = tokenConfig.token_lifetime || tokenConfig.accessTokenLifetime;
  if (accessTokenLifetime) {
    if (accessTokenLifetime > rules.accessTokenWarnMax) {
      findings.push({
        id: 'TOKEN_ACCESS_TOO_LONG',
        severity: 'HIGH',
        category: 'Token Security',
        title: 'Access token lifetime too long',
        description: `${context} has access token lifetime of ${accessTokenLifetime}s (${Math.round(accessTokenLifetime / 3600)}h). Maximum recommended: ${rules.accessTokenWarnMax}s.`,
        impact: 'Long-lived access tokens increase the window of opportunity for token abuse if compromised.',
        recommendation: `Reduce access token lifetime to ≤${rules.accessTokenWarnMax}s (${Math.round(rules.accessTokenWarnMax / 3600)}h). Use refresh tokens for extended sessions.`,
        resource: context,
        evidence: `${accessTokenLifetime}s`,
      });
    }
  }

  // Refresh token lifetime
  const refreshTokenLifetime = tokenConfig.token_lifetime_for_web || tokenConfig.refreshTokenLifetime;
  if (refreshTokenLifetime && refreshTokenLifetime > rules.refreshTokenWarnMax) {
    findings.push({
      id: 'TOKEN_REFRESH_TOO_LONG',
      severity: 'MEDIUM',
      category: 'Token Security',
      title: 'Refresh token lifetime too long',
      description: `${context} has refresh token lifetime of ${refreshTokenLifetime}s (${Math.round(refreshTokenLifetime / 86400)}d). Maximum recommended: ${rules.refreshTokenWarnMax}s.`,
      impact: 'Long-lived refresh tokens increase risk of persistent unauthorized access.',
      recommendation: `Reduce refresh token lifetime to ≤${Math.round(rules.refreshTokenWarnMax / 86400)} days. Implement refresh token rotation.`,
      resource: context,
      evidence: `${refreshTokenLifetime}s`,
    });
  }

  // Refresh token rotation
  if (tokenConfig.rotation_type === 'non-rotating') {
    findings.push({
      id: 'TOKEN_NO_ROTATION',
      severity: 'HIGH',
      category: 'Token Security',
      title: 'Refresh token rotation disabled',
      description: `${context} has non-rotating refresh tokens.`,
      impact: 'Without rotation, a stolen refresh token provides indefinite access until expiry.',
      recommendation: 'Enable refresh token rotation to limit the impact of token theft.',
      resource: context,
      evidence: 'rotation_type: non-rotating',
    });
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// CORS VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates CORS origin settings.
 *
 * @param {string[]} origins - Array of allowed origins
 * @param {string} context - Context description
 * @returns {Array<object>} Findings
 */
function validateCorsOrigins(origins, context) {
  const findings = [];
  if (!Array.isArray(origins)) return findings;

  for (const origin of origins) {
    if (typeof origin !== 'string') continue;
    for (const rule of config.deploymentRules.riskyCorsPatterns) {
      if (rule.pattern.test(origin)) {
        findings.push({
          id: rule.id,
          severity: rule.severity,
          category: 'IAM Security',
          title: `${rule.label} detected`,
          description: `${context} has a risky CORS origin: \`${origin}\``,
          impact: 'Permissive CORS origins may allow unauthorized cross-origin requests, leading to token theft or data exfiltration.',
          recommendation: 'Restrict CORS origins to specific, trusted domains. Remove wildcards and localhost entries.',
          resource: context,
          evidence: origin,
        });
      }
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// CLIENT / APPLICATION VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates client/application configuration.
 *
 * @param {object} client - Client configuration object
 * @param {string} context - Context description
 * @returns {Array<object>} Findings
 */
function validateClientConfig(client, context) {
  const findings = [];
  if (!client || typeof client !== 'object') return findings;

  // Check for public client without PKCE
  const appType = client.app_type || client.applicationType;
  const isPublic = appType === 'spa' || appType === 'native';
  if (isPublic) {
    const tokenEndpointAuth = client.token_endpoint_auth_method;
    if (tokenEndpointAuth !== 'none') {
      // SPA/Native should use PKCE with no client secret
    }
    // Check if PKCE is enforced
    if (client.oidc_conformant === false) {
      findings.push({
        id: 'CLIENT_NO_OIDC',
        severity: 'HIGH',
        category: 'IAM Security',
        title: 'OIDC conformant mode disabled',
        description: `${context} is a ${appType} application with OIDC conformant mode disabled.`,
        impact: 'Non-OIDC conformant mode uses legacy authentication which lacks modern security protections like PKCE.',
        recommendation: 'Enable OIDC conformant mode for all applications. Ensure PKCE is used for public clients.',
        resource: context,
        evidence: 'oidc_conformant: false',
      });
    }
  }

  // Check for wildcard in web_origins
  if (client.web_origins) {
    findings.push(...validateCorsOrigins(client.web_origins, context));
  }

  // Check callback URLs
  if (client.callbacks) {
    findings.push(...validateCallbackUrls(client.callbacks, context, 'callbacks'));
  }
  if (client.allowed_logout_urls) {
    findings.push(...validateCallbackUrls(client.allowed_logout_urls, context, 'allowed_logout_urls'));
  }
  if (client.allowed_origins) {
    findings.push(...validateCallbackUrls(client.allowed_origins, context, 'allowed_origins'));
  }

  // Check grant types
  if (client.grant_types) {
    findings.push(...validateGrantTypes(client.grant_types, context));
  }

  // Check token settings
  if (client.refresh_token) {
    findings.push(...validateTokenExpiry(client.refresh_token, context));
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// MFA / GUARDIAN VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates MFA/Guardian configuration.
 *
 * @param {object} guardianConfig - Guardian/MFA configuration
 * @param {string} context
 * @returns {Array<object>} Findings
 */
function validateMfaConfig(guardianConfig, context) {
  const findings = [];
  if (!guardianConfig || typeof guardianConfig !== 'object') return findings;

  // Check if MFA is disabled
  if (guardianConfig.enabled === false) {
    findings.push({
      id: 'MFA_DISABLED',
      severity: 'CRITICAL',
      category: 'MFA / Authentication',
      title: 'Multi-Factor Authentication is disabled',
      description: `${context}: MFA/Guardian is disabled.`,
      impact: 'Without MFA, accounts rely solely on passwords which are vulnerable to phishing, credential stuffing, and brute force attacks.',
      recommendation: 'Enable MFA for all users. At minimum, enforce MFA for privileged roles and admin access.',
      resource: context,
      evidence: 'enabled: false',
    });
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// CONNECTION VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates connection configuration.
 *
 * @param {object} connection - Connection configuration
 * @param {string} context
 * @returns {Array<object>} Findings
 */
function validateConnectionConfig(connection, context) {
  const findings = [];
  if (!connection || typeof connection !== 'object') return findings;

  // Check for disabled signup in database connections
  if (connection.strategy === 'auth0' && connection.options) {
    if (connection.options.disable_signup === false && connection.enabled_clients && connection.enabled_clients.length > 0) {
      // Open signup — may or may not be desired
      findings.push({
        id: 'CONN_OPEN_SIGNUP',
        severity: 'LOW',
        category: 'IAM Configuration',
        title: 'Open self-service signup enabled',
        description: `${context} has self-service signup enabled.`,
        impact: 'Open signup allows anyone to create accounts. Verify this is intended for the target environment.',
        recommendation: 'If self-service signup is not intended, set disable_signup to true.',
        resource: context,
        evidence: 'disable_signup: false',
      });
    }

    // Password policy
    if (connection.options.passwordPolicy === 'none' || connection.options.passwordPolicy === 'low') {
      findings.push({
        id: 'CONN_WEAK_PASSWORD',
        severity: 'HIGH',
        category: 'IAM Security',
        title: 'Weak password policy',
        description: `${context} has a "${connection.options.passwordPolicy || 'none'}" password policy.`,
        impact: 'Weak password policies allow users to set easily guessable passwords, increasing vulnerability to credential attacks.',
        recommendation: 'Set password policy to "good" or "excellent". Enforce minimum length, complexity, and breach detection.',
        resource: context,
        evidence: `passwordPolicy: ${connection.options.passwordPolicy || 'none'}`,
      });
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// RESOURCE SERVER / API VALIDATORS
// ─────────────────────────────────────────────────────────────

/**
 * Validates resource server (API) configuration.
 *
 * @param {object} resourceServer - API configuration object
 * @param {string} context
 * @returns {Array<object>} Findings
 */
function validateResourceServerConfig(resourceServer, context) {
  const findings = [];
  if (!resourceServer || typeof resourceServer !== 'object') return findings;

  // Check token lifetime
  if (resourceServer.token_lifetime) {
    findings.push(...validateTokenExpiry(
      { token_lifetime: resourceServer.token_lifetime },
      context
    ));
  }

  // Check for overly permissive scopes
  if (resourceServer.scopes && Array.isArray(resourceServer.scopes)) {
    const wildcardScopes = resourceServer.scopes.filter(s =>
      s.value === '*' || s.value === '*:*' || /^(read|write|admin):\*$/.test(s.value)
    );
    if (wildcardScopes.length > 0) {
      findings.push({
        id: 'API_PERMISSIVE_SCOPES',
        severity: 'HIGH',
        category: 'IAM Security',
        title: 'Overly permissive API scopes',
        description: `${context} defines wildcard scopes: ${wildcardScopes.map(s => s.value).join(', ')}`,
        impact: 'Wildcard scopes grant excessive permissions. If a token is compromised, the attacker gains broad access.',
        recommendation: 'Define granular, least-privilege scopes. Use specific resource:action patterns (e.g., "read:users", "write:orders").',
        resource: context,
        evidence: wildcardScopes.map(s => s.value).join(', '),
      });
    }
  }

  // Check if RBAC enforcement is disabled
  if (resourceServer.enforce_policies === false) {
    findings.push({
      id: 'API_RBAC_DISABLED',
      severity: 'MEDIUM',
      category: 'IAM Configuration',
      title: 'RBAC enforcement disabled on API',
      description: `${context} has RBAC policy enforcement disabled.`,
      impact: 'Without RBAC enforcement, permissions assigned through roles are not automatically included in access tokens.',
      recommendation: 'Enable "Enforce Policies" to include RBAC permissions in access tokens.',
      resource: context,
      evidence: 'enforce_policies: false',
    });
  }

  return findings;
}

module.exports = {
  validateCallbackUrls,
  validateGrantTypes,
  validateTokenExpiry,
  validateCorsOrigins,
  validateClientConfig,
  validateMfaConfig,
  validateConnectionConfig,
  validateResourceServerConfig,
};
