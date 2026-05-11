/**
 * AuthGuardian AI — Diff Parser
 * ==============================
 * Parses git diff output to identify changed Auth0 configuration files.
 * Classifies changes by Auth0 resource type, change type (added/modified/deleted),
 * and extracts file content for downstream analysis.
 *
 * @module diff-parser
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const config = require('../../configs/review-config');

/**
 * Auth0 resource type mapping — maps directory/file patterns to resource types
 */
const RESOURCE_PATH_MAP = [
  { pattern: /actions\//i,           type: 'actions' },
  { pattern: /rules\//i,             type: 'rules' },
  { pattern: /hooks\//i,             type: 'hooks' },
  { pattern: /clients\//i,           type: 'clients' },
  { pattern: /connections\//i,       type: 'connections' },
  { pattern: /databases?\//i,        type: 'databases' },
  { pattern: /resource[_-]?servers?\//i, type: 'resourceServers' },
  { pattern: /client[_-]?grants?\//i, type: 'clientGrants' },
  { pattern: /roles\//i,             type: 'roles' },
  { pattern: /prompts?\//i,          type: 'prompts' },
  { pattern: /branding\//i,          type: 'branding' },
  { pattern: /email[_-]?templates?\//i, type: 'emailTemplates' },
  { pattern: /pages\//i,             type: 'pages' },
  { pattern: /tenant\.ya?ml$/i,      type: 'tenant' },
  { pattern: /guardian\//i,          type: 'guardian' },
  { pattern: /triggers?\//i,         type: 'triggers' },
  { pattern: /attack[_-]?protection/i, type: 'attackProtection' },
  { pattern: /organizations?\//i,    type: 'organizations' },
  { pattern: /custom[_-]?domains?\//i, type: 'customDomains' },
  { pattern: /themes?\//i,           type: 'themes' },
];

/**
 * Determines the Auth0 resource type for a given file path.
 *
 * @param {string} filePath - Relative file path
 * @returns {string} Auth0 resource type identifier
 */
function classifyResourceType(filePath) {
  for (const mapping of RESOURCE_PATH_MAP) {
    if (mapping.pattern.test(filePath)) {
      return mapping.type;
    }
  }
  return 'unknown';
}

/**
 * Determines if a file is an Auth0-related configuration file.
 *
 * @param {string} filePath - Relative file path
 * @returns {boolean}
 */
function isAuth0File(filePath) {
  const normalizedPath = filePath.replace(/\\/g, '/');
  return config.diffParser.auth0Paths.some(p => normalizedPath.startsWith(p));
}

/**
 * Determines if a file contains executable code (Actions, Rules, Hooks).
 *
 * @param {string} filePath - Relative file path
 * @returns {boolean}
 */
function isCodeFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const codeExtensions = ['.js', '.ts', '.mjs'];
  const codeResourceTypes = ['actions', 'rules', 'hooks'];
  const resourceType = classifyResourceType(filePath);
  return codeExtensions.includes(ext) || codeResourceTypes.includes(resourceType);
}

/**
 * Safely reads file content, returning null if file doesn't exist.
 *
 * @param {string} filePath - Absolute or relative file path
 * @returns {string|null}
 */
function safeReadFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Runs git diff and returns list of changed files with metadata.
 *
 * @param {object} options
 * @param {string} [options.baseBranch] - Git ref to diff against
 * @param {string} [options.workDir] - Working directory
 * @returns {Array<object>} Array of changed file descriptors
 */
function getChangedFiles(options = {}) {
  const baseBranch = options.baseBranch || process.env.AUTHGUARDIAN_BASE_REF || config.diffParser.baseBranch;
  const workDir = options.workDir || process.cwd();

  let diffOutput;
  try {
    // Try diffing against the base branch
    diffOutput = execSync(
      `git diff --name-status ${baseBranch}...HEAD`,
      { cwd: workDir, encoding: 'utf8', timeout: 30000 }
    ).trim();
  } catch {
    try {
      // Fallback: diff against HEAD~1
      diffOutput = execSync(
        'git diff --name-status HEAD~1',
        { cwd: workDir, encoding: 'utf8', timeout: 30000 }
      ).trim();
    } catch {
      // Final fallback: show all tracked files as 'added'
      console.warn('[AuthGuardian] Could not determine git diff. Scanning all Auth0 files.');
      return scanAllAuth0Files(workDir);
    }
  }

  if (!diffOutput) {
    console.warn('[AuthGuardian] No changed files detected in diff. Falling back to filesystem scan.');
    return scanAllAuth0Files(workDir);
  }

  const parsed = parseDiffOutput(diffOutput, workDir);

  // If diff found changes but none were Auth0 files, fall back to filesystem scan
  if (parsed.length === 0) {
    console.warn('[AuthGuardian] Diff found changes but no Auth0 files. Falling back to filesystem scan.');
    return scanAllAuth0Files(workDir);
  }

  return parsed;
}

/**
 * Parses raw git diff --name-status output.
 *
 * @param {string} diffOutput - Raw output from git diff --name-status
 * @param {string} workDir - Working directory for reading file content
 * @returns {Array<object>}
 */
function parseDiffOutput(diffOutput, workDir) {
  const lines = diffOutput.split('\n').filter(line => line.trim());
  const changes = [];

  for (const line of lines) {
    const parts = line.split('\t');
    if (parts.length < 2) continue;

    const statusCode = parts[0].trim().charAt(0).toUpperCase();
    const filePath = parts[parts.length - 1].trim();

    // Filter: only Auth0-related files
    if (!isAuth0File(filePath)) continue;

    // Filter: only analyzable extensions
    const ext = path.extname(filePath).toLowerCase();
    if (!config.diffParser.analyzableExtensions.includes(ext) && ext !== '') continue;

    const changeType = mapStatusToChangeType(statusCode);
    const resourceType = classifyResourceType(filePath);
    const absolutePath = path.resolve(workDir, filePath);
    const content = changeType !== 'deleted' ? safeReadFile(absolutePath) : null;

    changes.push({
      filePath,
      absolutePath,
      changeType,       // 'added' | 'modified' | 'deleted'
      statusCode,       // Git status letter (A, M, D, R, C)
      resourceType,     // Auth0 resource type
      isCode: isCodeFile(filePath),
      extension: ext,
      content,
      resourceMeta: config.resourceTypes[resourceType] || { label: 'Unknown', risk: 'MEDIUM', icon: '❓' },
    });
  }

  return changes;
}

/**
 * Maps a git status code to a human-readable change type.
 *
 * @param {string} code - Single-character git status code
 * @returns {string}
 */
function mapStatusToChangeType(code) {
  const map = {
    'A': 'added',
    'M': 'modified',
    'D': 'deleted',
    'R': 'modified',  // renamed = modified
    'C': 'added',     // copied = added
    'T': 'modified',  // type change
    'U': 'modified',  // unmerged
  };
  return map[code] || 'modified';
}

/**
 * Fallback: Scans all Auth0 files in the working directory.
 *
 * @param {string} workDir
 * @returns {Array<object>}
 */
function scanAllAuth0Files(workDir) {
  const changes = [];
  const auth0Dir = path.join(workDir, 'auth0');

  if (!fs.existsSync(auth0Dir)) return changes;

  function walkDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkDir(fullPath);
      } else {
        const relativePath = path.relative(workDir, fullPath).replace(/\\/g, '/');
        const ext = path.extname(entry.name).toLowerCase();
        if (!config.diffParser.analyzableExtensions.includes(ext)) continue;
        const resourceType = classifyResourceType(relativePath);
        changes.push({
          filePath: relativePath,
          absolutePath: fullPath,
          changeType: 'added',
          statusCode: 'A',
          resourceType,
          isCode: isCodeFile(relativePath),
          extension: ext,
          content: safeReadFile(fullPath),
          resourceMeta: config.resourceTypes[resourceType] || { label: 'Unknown', risk: 'MEDIUM', icon: '❓' },
        });
      }
    }
  }

  walkDir(auth0Dir);
  return changes;
}

/**
 * Groups changed files by resource type.
 *
 * @param {Array<object>} changes
 * @returns {object} Map of resourceType → Array<change>
 */
function groupByResourceType(changes) {
  return changes.reduce((grouped, change) => {
    const key = change.resourceType;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(change);
    return grouped;
  }, {});
}

/**
 * Groups changed files by change type.
 *
 * @param {Array<object>} changes
 * @returns {object} { added: [...], modified: [...], deleted: [...] }
 */
function groupByChangeType(changes) {
  return {
    added: changes.filter(c => c.changeType === 'added'),
    modified: changes.filter(c => c.changeType === 'modified'),
    deleted: changes.filter(c => c.changeType === 'deleted'),
  };
}

module.exports = {
  getChangedFiles,
  parseDiffOutput,
  classifyResourceType,
  isAuth0File,
  isCodeFile,
  groupByResourceType,
  groupByChangeType,
  safeReadFile,
};
