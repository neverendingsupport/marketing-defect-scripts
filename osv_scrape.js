#!/usr/bin/env node
import fs from "fs/promises";
import https from "https";
import path from "path";

// -------- CONFIG --------
const CONCURRENCY = 2;
const RETRY_LIMIT = 5;
const INITIAL_DELAY = 1000;

const OSV_HOST = "api.osv.dev";
const OSV_PATH = "/v1/query";

const allVulns = new Map();
const perPackageCounts = new Map();

// -------- Helper Functions --------
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// -------- Helper Functions --------
function compareSemver(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

function isVulnerableAtOrBelow(vuln, targetVersion) {
  if (!vuln.affected) return false;

  return vuln.affected.some((a) =>
    (a.ranges || []).some((r) => {
      let introduced = null;
      let fixed = null;

      for (const e of r.events || []) {
        if (e.introduced !== undefined) introduced = e.introduced;
        if (e.fixed !== undefined) fixed = e.fixed;
      }

      // Default introduced = 0.0.0 if not set
      if (!introduced || introduced === "0") introduced = "0.0.0";

      // target must be >= introduced
      if (compareSemver(targetVersion, introduced) < 0) {
        return false;
      }

      // target must be <= fixed (if fixed exists)
      if (fixed && compareSemver(targetVersion, fixed) > 0) {
        return false;
      }

      return true;
    })
  );
}

function httpsPost(path, data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const options = {
      hostname: OSV_HOST,
      path,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
    };

    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        if (res.statusCode === 429 || res.statusCode >= 500) {
          const err = new Error(`Status ${res.statusCode}`);
          err.retryable = true;
          return reject(err);
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`HTTP ${res.statusCode}: ${body}`));
        }
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function parsePurl(purl) {
  // Example: "pkg:composer/symfony/console@5.3.0"
  const regex = /^pkg:([^\/]+)\/([^@]+)(?:@(.+))?/;
  const match = regex.exec(purl);

  if (!match) return null;

  let registry = match[1];
  if (registry === "gem") {
    registry = "RubyGems";
  }

  if (registry === "maven") {
    registry = "Maven";
  }

  if (registry === "composer") {
    registry = "Packagist";
  }

  const component = match[2]; // e.g., "symfony/console"
  const version = match[3] || null; // e.g., "5.3.0"

  return { registry, component, version };
}

async function osvRequest(pkg, attempt = 1) {
  try {
    const data = await httpsPost(OSV_PATH, {
      package: {
        purl: pkg.component,
      },
    });
    return data.vulns || [];
  } catch (err) {
    if (err.retryable && attempt <= RETRY_LIMIT) {
      const delay = INITIAL_DELAY * 2 ** (attempt - 1);
      console.warn(`Rate limited (attempt ${attempt}) → waiting ${delay}ms`);
      await sleep(delay);
      return osvRequest(pkg, attempt + 1);
    }
    console.error(`${pkg.component}@${pkg.forkPoint}: ${err.message}`);
    return [];
  }
}

function extractFixes(v) {
  const fixes = new Set();
  (v.affected || []).forEach((a) =>
    (a.ranges || []).forEach((r) =>
      (r.events || []).forEach((e) => {
        if (e.fixed) fixes.add(e.fixed);
      })
    )
  );
  return [...fixes];
}

// -------- Worker --------
async function worker(queue) {
  while (queue.length) {
    const pkg = queue.shift();
    console.log(`Querying ${pkg.component}`);
    const vulns = await osvRequest(pkg);

    if (!vulns.length) {
      console.log("No vulns for ", pkg.component);
      continue;
    }

    // Filter out vulns not affecting this forkPoint
    const relevantVulns = vulns.filter((v) =>
      isVulnerableAtOrBelow(v, pkg.forkPoint)
    );

    let remediatedCount = 0;
    for (const v of relevantVulns) {
      const fixes = extractFixes(v);
      if (fixes.length > 0) remediatedCount++;

      if (!allVulns.has(v.id)) {
        allVulns.set(v.id, {
          id: v.id,
          summary: v.summary || "",
          details: v.details || "",
          severity: v.severity || [],
          affected: v.affected || [],
          fixedVersions: fixes,
          references: (v.references || []).map((r) => r.url),
          affectedComponents: [pkg.component],
        });
      } else {
        const ex = allVulns.get(v.id);
        ex.fixedVersions = [...new Set([...ex.fixedVersions, ...fixes])];
        if (!ex.affectedComponents.includes(pkg.component)) {
          ex.affectedComponents.push(pkg.component);
        }
      }
    }

    perPackageCounts.set(pkg.component, remediatedCount);
  }
}

// -------- Main --------
(async () => {
  // Read packages from local file
  const packagesPath = path.resolve("./componentsWithForkPoints.json");
  let packages;
  try {
    const fileData = await fs.readFile(packagesPath, "utf-8");
    packages = JSON.parse(fileData);
  } catch (err) {
    console.error(`Failed to read packages.json: ${err.message}`);
    process.exit(1);
  }

  console.log(`Checking ${packages.length} components`);
  const queue = [...packages];
  const workers = Array.from({ length: CONCURRENCY }, () => worker(queue));
  await Promise.all(workers);

  const vulnList = [...allVulns.values()];
  await fs.writeFile("osv-results.json", JSON.stringify(vulnList, null, 2));

  console.log("\nRemediated vulnerabilities per component:");
  for (const [comp, count] of perPackageCounts) {
    console.log(`${comp}: ${count}`);
  }

  console.log(
    `\n✅ Saved ${vulnList.length} unique vulnerabilities to osv-results.json`
  );
})();
