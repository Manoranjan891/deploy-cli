/**
 * AuthGuardian AI — Utility Module
 * ==================================
 * Reusable helper functions used across all review engine modules.
 *
 * @module utils
 */

const fs = require('fs');
const path = require('path');

/**
 * Formats a timestamp as ISO 8601 string.
 *
 * @param {Date} [date] - Date to format (defaults to now)
 * @returns {string} ISO 8601 timestamp
 */
function formatTimestamp(date = new Date()) {
  return date.toISOString();
}

/**
 * Safely parses JSON with fallback.
 *
 * @param {string} jsonString
 * @param {*} fallback - Value to return on parse failure
 * @returns {*}
 */
function safeJsonParse(jsonString, fallback = null) {
  try {
    return JSON.parse(jsonString);
  } catch {
    return fallback;
  }
}

/**
 * Deep-clones an object (JSON-safe only).
 *
 * @param {*} obj
 * @returns {*}
 */
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Truncates a string to a maximum length.
 *
 * @param {string} str
 * @param {number} maxLength
 * @returns {string}
 */
function truncate(str, maxLength = 200) {
  if (!str || str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

/**
 * Ensures a directory exists, creating it recursively if needed.
 *
 * @param {string} dirPath
 */
function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

/**
 * Reads a file safely, returning null on failure.
 *
 * @param {string} filePath
 * @returns {string|null}
 */
function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Writes content to a file, creating directories as needed.
 *
 * @param {string} filePath
 * @param {string} content
 */
function writeFileSafe(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, content, 'utf8');
}

/**
 * Returns a human-readable duration string.
 *
 * @param {number} ms - Duration in milliseconds
 * @returns {string}
 */
function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

/**
 * Deduplicates an array of findings by ID.
 *
 * @param {Array<object>} findings
 * @returns {Array<object>}
 */
function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.id}-${f.file || ''}-${f.evidence || ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Creates an audit log entry.
 *
 * @param {object} params
 * @returns {object} Audit log entry
 */
function createAuditEntry({ action, actor, details, findings, timestamp }) {
  return {
    timestamp: timestamp || formatTimestamp(),
    action,
    actor: actor || 'AuthGuardian AI',
    details,
    findingsSummary: findings ? {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
    } : undefined,
    engineVersion: require('../../configs/review-config').meta.version,
  };
}

/**
 * Generates a unique run ID for tracking.
 *
 * @returns {string}
 */
function generateRunId() {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `ag-${timestamp}-${random}`;
}

/**
 * Sets a GitHub Actions output variable.
 *
 * @param {string} name - Output name
 * @param {string} value - Output value
 */
function setGitHubOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath) {
    fs.appendFileSync(outputPath, `${name}=${value}\n`);
  }
}

/**
 * Gets environment info for context.
 *
 * @returns {object}
 */
function getEnvironmentInfo() {
  return {
    isCI: !!process.env.CI,
    isGitHubActions: !!process.env.GITHUB_ACTIONS,
    repository: process.env.GITHUB_REPOSITORY || 'local',
    branch: process.env.GITHUB_REF_NAME || process.env.GITHUB_HEAD_REF || 'unknown',
    commit: process.env.GITHUB_SHA ? process.env.GITHUB_SHA.substring(0, 7) : 'local',
    runId: process.env.GITHUB_RUN_ID || generateRunId(),
    actor: process.env.GITHUB_ACTOR || 'local',
    workflow: process.env.GITHUB_WORKFLOW || 'local',
  };
}

module.exports = {
  formatTimestamp,
  safeJsonParse,
  deepClone,
  truncate,
  ensureDir,
  readFileSafe,
  writeFileSafe,
  formatDuration,
  deduplicateFindings,
  createAuditEntry,
  generateRunId,
  setGitHubOutput,
  getEnvironmentInfo,
};
