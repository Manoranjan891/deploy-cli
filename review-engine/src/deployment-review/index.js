/**
 * AuthGuardian AI — Deployment Review Engine
 * =============================================
 * Analyzes changed Auth0 configuration files for IAM/security risks.
 * Parses YAML/JSON configurations and runs them through the validator suite.
 *
 * This is FEATURE 1 — AI-Powered Auth0 Deployment Review Bot.
 *
 * @module deployment-review
 */

const yaml = require('js-yaml');
const config = require('../../configs/review-config');
const validators = require('../validators');
const { groupByResourceType, groupByChangeType } = require('../diff-parser');

/**
 * Runs deployment review on all changed files.
 *
 * @param {Array<object>} changedFiles - Output from diff-parser
 * @returns {object} { findings, summary, reviewedFiles }
 */
function runDeploymentReview(changedFiles) {
  const findings = [];
  const reviewedFiles = [];

  for (const file of changedFiles) {
    // Skip deleted files (nothing to validate) and code-only files (handled by code review)
    if (file.changeType === 'deleted') {
      reviewedFiles.push({ ...file, findings: [], skipped: true, reason: 'Deleted file' });
      continue;
    }

    if (!file.content) {
      reviewedFiles.push({ ...file, findings: [], skipped: true, reason: 'No content available' });
      continue;
    }

    const fileFindings = analyzeFile(file);
    findings.push(...fileFindings);
    reviewedFiles.push({ ...file, findings: fileFindings, skipped: false });
  }

  // Analyze cross-file concerns
  const crossFileFindings = analyzeCrossFileConcerns(changedFiles);
  findings.push(...crossFileFindings);

  const byResource = groupByResourceType(changedFiles);
  const byChange = groupByChangeType(changedFiles);

  return {
    findings,
    reviewedFiles,
    stats: {
      totalFiles: changedFiles.length,
      added: byChange.added.length,
      modified: byChange.modified.length,
      deleted: byChange.deleted.length,
      resourceTypes: Object.keys(byResource),
      totalFindings: findings.length,
    },
  };
}

/**
 * Analyzes a single Auth0 configuration file.
 *
 * @param {object} file - File descriptor from diff-parser
 * @returns {Array<object>} Findings for this file
 */
function analyzeFile(file) {
  const parsed = parseFileContent(file);
  if (!parsed) return [];

  const context = `${file.resourceMeta.icon} ${file.resourceMeta.label} — \`${file.filePath}\``;
  const findings = [];

  // Route to appropriate validators based on resource type
  switch (file.resourceType) {
    case 'clients':
      findings.push(...analyzeClients(parsed, context, file));
      break;
    case 'connections':
    case 'databases':
      findings.push(...analyzeConnections(parsed, context, file));
      break;
    case 'resourceServers':
      findings.push(...analyzeResourceServers(parsed, context, file));
      break;
    case 'guardian':
      findings.push(...analyzeGuardian(parsed, context, file));
      break;
    case 'tenant':
      findings.push(...analyzeTenant(parsed, context, file));
      break;
    case 'roles':
      findings.push(...analyzeRoles(parsed, context, file));
      break;
    case 'clientGrants':
      findings.push(...analyzeClientGrants(parsed, context, file));
      break;
    default:
      // Generic analysis for other resource types
      findings.push(...analyzeGenericResource(parsed, context, file));
      break;
  }

  // Tag all findings with file info
  return findings.map(f => ({
    ...f,
    file: file.filePath,
    resourceType: file.resourceType,
    changeType: file.changeType,
  }));
}

/**
 * Parses YAML or JSON file content into a JavaScript object.
 *
 * @param {object} file - File descriptor
 * @returns {*} Parsed content or null
 */
function parseFileContent(file) {
  try {
    if (file.extension === '.yaml' || file.extension === '.yml') {
      return yaml.load(file.content);
    }
    if (file.extension === '.json') {
      return JSON.parse(file.content);
    }
    // For .js files used as config, attempt JSON parse of exports
    return null;
  } catch (err) {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────
// RESOURCE-SPECIFIC ANALYZERS
// ─────────────────────────────────────────────────────────────

/**
 * Analyzes client/application configurations.
 */
function analyzeClients(parsed, context, file) {
  const findings = [];
  const clients = normalizeToArray(parsed);

  for (const client of clients) {
    const clientName = client.name || client.client_name || 'Unknown Client';
    const clientContext = `Application "${clientName}" (${context})`;
    findings.push(...validators.validateClientConfig(client, clientContext));
  }

  return findings;
}

/**
 * Analyzes connection configurations.
 */
function analyzeConnections(parsed, context, file) {
  const findings = [];
  const connections = normalizeToArray(parsed);

  for (const conn of connections) {
    const connName = conn.name || 'Unknown Connection';
    const connContext = `Connection "${connName}" (${context})`;
    findings.push(...validators.validateConnectionConfig(conn, connContext));
  }

  return findings;
}

/**
 * Analyzes resource server (API) configurations.
 */
function analyzeResourceServers(parsed, context, file) {
  const findings = [];
  const servers = normalizeToArray(parsed);

  for (const server of servers) {
    const serverName = server.name || server.identifier || 'Unknown API';
    const serverContext = `API "${serverName}" (${context})`;
    findings.push(...validators.validateResourceServerConfig(server, serverContext));
  }

  return findings;
}

/**
 * Analyzes Guardian/MFA configurations.
 */
function analyzeGuardian(parsed, context, file) {
  const findings = [];
  const configs = normalizeToArray(parsed);

  for (const guardianCfg of configs) {
    findings.push(...validators.validateMfaConfig(guardianCfg, context));
  }

  return findings;
}

/**
 * Analyzes tenant-level settings (tenant.yaml).
 * The tenant file often contains embedded client, connection, and other configs.
 */
function analyzeTenant(parsed, context, file) {
  const findings = [];

  if (!parsed || typeof parsed !== 'object') return findings;

  // Analyze embedded clients
  if (parsed.clients && Array.isArray(parsed.clients)) {
    for (const client of parsed.clients) {
      const clientName = client.name || 'Unknown Client';
      findings.push(...validators.validateClientConfig(client, `Application "${clientName}"`));
    }
  }

  // Analyze embedded connections
  if (parsed.connections && Array.isArray(parsed.connections)) {
    for (const conn of parsed.connections) {
      const connName = conn.name || 'Unknown Connection';
      findings.push(...validators.validateConnectionConfig(conn, `Connection "${connName}"`));
    }
  }

  // Analyze embedded databases
  if (parsed.databases && Array.isArray(parsed.databases)) {
    for (const db of parsed.databases) {
      const dbName = db.name || 'Unknown Database';
      findings.push(...validators.validateConnectionConfig(db, `Database "${dbName}"`));
    }
  }

  // Analyze embedded resource servers
  if (parsed.resourceServers && Array.isArray(parsed.resourceServers)) {
    for (const rs of parsed.resourceServers) {
      const rsName = rs.name || rs.identifier || 'Unknown API';
      findings.push(...validators.validateResourceServerConfig(rs, `API "${rsName}"`));
    }
  }

  // Analyze client grants
  if (parsed.clientGrants && Array.isArray(parsed.clientGrants)) {
    findings.push(...analyzeClientGrantsList(parsed.clientGrants));
  }

  // Analyze guardian settings at tenant level
  if (parsed.guardianFactors) {
    for (const factor of normalizeToArray(parsed.guardianFactors)) {
      findings.push(...validators.validateMfaConfig(factor, `Guardian Factor "${factor.name || 'unknown'}"`));
    }
  }

  return findings;
}

/**
 * Analyzes role configurations.
 */
function analyzeRoles(parsed, context, file) {
  const findings = [];
  const roles = normalizeToArray(parsed);

  for (const role of roles) {
    const roleName = role.name || 'Unknown Role';
    // Check for overly permissive role descriptions
    if (role.permissions && Array.isArray(role.permissions)) {
      const wildcardPerms = role.permissions.filter(p =>
        p.permission_name === '*' || p.permission_name === '*:*'
      );
      if (wildcardPerms.length > 0) {
        findings.push({
          id: 'ROLE_WILDCARD_PERMS',
          severity: 'HIGH',
          category: 'IAM Security',
          title: `Role "${roleName}" has wildcard permissions`,
          description: `Role "${roleName}" (${context}) has overly permissive wildcard permissions.`,
          impact: 'Wildcard permissions grant unrestricted access. Users assigned this role gain full control.',
          recommendation: 'Replace wildcard permissions with specific, least-privilege permissions.',
          resource: `Role "${roleName}"`,
          evidence: wildcardPerms.map(p => p.permission_name).join(', '),
        });
      }
    }
  }

  return findings;
}

/**
 * Analyzes client grant configurations.
 */
function analyzeClientGrants(parsed, context, file) {
  const findings = [];
  const grants = normalizeToArray(parsed);
  findings.push(...analyzeClientGrantsList(grants));
  return findings;
}

/**
 * Checks client grants list for excessive scopes.
 */
function analyzeClientGrantsList(grants) {
  const findings = [];

  for (const grant of grants) {
    if (grant.scope && Array.isArray(grant.scope)) {
      // Check for grants with extremely broad scopes
      const mgmtApiScopes = grant.scope.filter(s => s.includes(':'));
      if (mgmtApiScopes.length > 20) {
        findings.push({
          id: 'GRANT_EXCESSIVE_SCOPES',
          severity: 'MEDIUM',
          category: 'IAM Security',
          title: 'Client grant with excessive scopes',
          description: `Client grant for audience "${grant.audience || 'unknown'}" has ${mgmtApiScopes.length} scopes assigned.`,
          impact: 'Excessive scopes increase blast radius if client credentials are compromised.',
          recommendation: 'Review and minimize granted scopes to only those required by the application.',
          resource: `Client Grant → ${grant.audience || 'unknown'}`,
          evidence: `${mgmtApiScopes.length} scopes`,
        });
      }
    }
  }

  return findings;
}

/**
 * Generic analysis for resource types without specialized analyzers.
 */
function analyzeGenericResource(parsed, context, file) {
  const findings = [];

  // Deep-scan for any callback/redirect URLs in the parsed content
  const urls = extractUrlsFromObject(parsed);
  if (urls.length > 0) {
    findings.push(...validators.validateCallbackUrls(urls, context, 'embedded URLs'));
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// CROSS-FILE ANALYSIS
// ─────────────────────────────────────────────────────────────

/**
 * Analyzes concerns that span multiple files.
 */
function analyzeCrossFileConcerns(changedFiles) {
  const findings = [];
  const byResource = groupByResourceType(changedFiles);

  // Check if MFA/guardian configs are being modified along with connection changes
  if (byResource.guardian && byResource.connections) {
    findings.push({
      id: 'CROSS_MFA_CONNECTION_CHANGE',
      severity: 'MEDIUM',
      category: 'Governance',
      title: 'Simultaneous MFA and connection changes detected',
      description: 'Both Guardian/MFA settings and connections are being modified in the same deployment.',
      impact: 'Changing MFA and connection settings simultaneously may lead to authentication disruptions.',
      recommendation: 'Consider deploying MFA and connection changes separately to reduce blast radius.',
      resource: 'Cross-file analysis',
      evidence: `Guardian files: ${byResource.guardian.length}, Connection files: ${byResource.connections.length}`,
    });
  }

  // Check if many resources are being deleted
  const deletedFiles = changedFiles.filter(f => f.changeType === 'deleted');
  if (deletedFiles.length >= 5) {
    findings.push({
      id: 'CROSS_MASS_DELETION',
      severity: 'HIGH',
      category: 'Governance',
      title: 'Mass deletion detected',
      description: `${deletedFiles.length} Auth0 resources are being deleted in this deployment.`,
      impact: 'Mass deletion may remove critical IAM configurations, potentially disrupting authentication.',
      recommendation: 'Verify all deletions are intentional. Consider staged rollout for large-scale changes.',
      resource: 'Cross-file analysis',
      evidence: deletedFiles.map(f => f.filePath).join(', '),
    });
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────

/**
 * Normalizes parsed content to an array for uniform processing.
 */
function normalizeToArray(data) {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object') return [data];
  return [];
}

/**
 * Recursively extracts URL strings from an object.
 */
function extractUrlsFromObject(obj, urls = []) {
  if (!obj || typeof obj !== 'object') return urls;

  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string' && /^https?:\/\//i.test(value)) {
      urls.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string' && /^https?:\/\//i.test(item)) {
          urls.push(item);
        } else if (typeof item === 'object') {
          extractUrlsFromObject(item, urls);
        }
      }
    } else if (typeof value === 'object') {
      extractUrlsFromObject(value, urls);
    }
  }

  return urls;
}

module.exports = {
  runDeploymentReview,
  analyzeFile,
  parseFileContent,
};
