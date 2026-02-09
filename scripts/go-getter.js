#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const { spawn } = require("node:child_process");

const repoRoot = path.resolve(__dirname, "..");

function log(message) {
  console.log(`[go-getter] ${message}`);
}

async function getCommitSha() {
  return exec("git", ["-C", repoRoot, "rev-parse", "HEAD"])
    .then((result) => result.stdout.trim());
}

async function listGoModFiles(startDir) {
  const results = [];
  async function walk(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === "node_modules") {
        continue;
      }
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && entry.name === "go.mod") {
        results.push(fullPath);
      }
    }
  }
  await walk(startDir);
  return results;
}

async function listModules() {
  const goModFiles = await listGoModFiles(repoRoot);
  const modules = [];
  for (const filePath of goModFiles) {
    const content = await fsp.readFile(filePath, "utf8");
    const match = content.match(/^module\s+(.+)\s*$/m);
    if (match && match[1]) {
      modules.push(match[1].trim());
    }
  }
  return modules.sort();
}

async function moduleFromDir(moduleDir) {
  const goModPath = path.join(repoRoot, moduleDir, "go.mod");
  const content = await fsp.readFile(goModPath, "utf8");
  const match = content.match(/^module\s+(.+)\s*$/m);
  if (!match || !match[1]) {
    throw new Error(`module directive not found in ${goModPath}`);
  }
  return match[1].trim();
}

function exec(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...options,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        const error = new Error(
          `${command} ${args.join(" ")} failed with code ${code}`
        );
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

async function run() {
  const moduleArgs = process.argv.slice(2);
  const [commitSha, modules] = await Promise.all([
    getCommitSha(),
    moduleArgs.length > 0
      ? Promise.all(moduleArgs.map((dir) => moduleFromDir(dir)))
      : listModules(),
  ]);

  if (modules.length === 0) {
    console.log("No go.mod files found.");
    return;
  }

  const tasks = modules.map((mod) => {
    const spec = `${mod}@${commitSha}`;
    return (async () => {
      const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "go-getter-"));
      try {
        await exec("go", ["mod", "init", "go-getter-temp"], { cwd: tmpDir });
        log(`trying ${spec}...`);
        const result = await exec("go", ["get", "-v", spec], { cwd: tmpDir });
        return { mod, result };
      } catch (error) {
        return { mod, error };
      } finally {
        log(`cleaning up ${tmpDir}`);
        await fsp.rm(tmpDir, { recursive: true, force: true });
      }
    })();
  });

  const results = await Promise.all(tasks);

  let failed = false;
  for (const entry of results) {
    if (entry.error) {
      failed = true;
      console.error(`go get failed for ${entry.mod}`);
      if (entry.error.stderr) {
        console.error(entry.error.stderr.trim());
      }
      continue;
    }
    if (entry.result.stdout.trim()) {
      console.log(entry.result.stdout.trim());
    }
    if (entry.result.stderr.trim()) {
      console.error(entry.result.stderr.trim());
    }
  }

  if (failed) {
    log("one or more modules failed");
    process.exitCode = 1;
  } else {
    log("all modules fetched successfully");
  }
}

run().catch((error) => {
  console.error(error.message || error);
  if (error.stderr) {
    console.error(error.stderr.trim());
  }
  process.exit(1);
});
