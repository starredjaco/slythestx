import { Router, Request, Response } from "express";
import { exec } from 'child_process';
import { promisify } from 'util';
import net from "net";
import path from "path";
import fs from "fs";
import multer from "multer";

const execAsync = promisify(exec);
const router = Router();

const TMP_DIR = "/tmp/adb-work";
const EXTRACTED_DIR = "/app/uploads/extracted";
const APK_EDITOR_PATH = "/app/tools/APKEditor.jar";

if (!fs.existsSync(TMP_DIR)) {
  fs.mkdirSync(TMP_DIR, { recursive: true });
}
if (!fs.existsSync(EXTRACTED_DIR)) {
  fs.mkdirSync(EXTRACTED_DIR, { recursive: true });
}

// ==================== CONFIG ====================
let adbConfig = {
  host: "127.0.0.1",
  port: 5037,
  deviceId: "",
  wireless: false,
  autoConnect: true,
  useHostADB: false
};

function isValidDeviceId(id: string): boolean {
  if (!id || id.length > 64) return false;
  return /^[a-zA-Z0-9.\-:_]+$/.test(id);
}

function isValidIp(ip: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split('.').every(n => parseInt(n) <= 255);
}

function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port <= 65535;
}


function isValidPackageName(pkg: string): boolean {
  if (!pkg || pkg.length > 255) return false;
  return /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/.test(pkg);
}


function isValidDevicePath(p: string): boolean {
  const shellInjection = /[;&|`$(){}[\]<>'"\\!]/;
  if (shellInjection.test(p)) {
    return false;
  }
  if (!p.startsWith('/')) {
    return false;
  }
  if (p.includes('..')) {
    return false;
  }
  
  return true;
}

function escapeShellArg(arg: string): string {
  return arg
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\$/g, '\\$')
    .replace(/`/g, '\\`')
    .replace(/!/g, '\\!');
}

function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_');
}

// ==================== ADB TCP CLIENT ====================
function adbQuery(command: string, timeout = 5000): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = new net.Socket();
    client.setTimeout(timeout);

    client.connect(adbConfig.port, adbConfig.host, () => {
      const payload = command.length.toString(16).padStart(4, "0") + command;
      client.write(payload);
    });

    let data = "";

    client.on("data", chunk => {
      data += chunk.toString();
    });

    client.on("close", () => {
      resolve(data);
    });

    client.on("error", (err) => {
      reject(err);
    });

    client.on("timeout", () => {
      client.destroy();
      reject(new Error("Connection timeout"));
    });
  });
}

function parseAdbResponse(raw: string): { success: boolean; data: string } {
  if (raw.startsWith("OKAY")) {
    const lengthHex = raw.substring(4, 8);
    const length = parseInt(lengthHex, 16);
    if (!isNaN(length)) {
      return { success: true, data: raw.substring(8, 8 + length) };
    }
    return { success: true, data: raw.substring(4) };
  }
  if (raw.startsWith("FAIL")) {
    return { success: false, data: raw.substring(8) };
  }
  return { success: true, data: raw };
}

async function adbShell(command: string, timeout = 15000): Promise<string> {
  const deviceSerial = adbConfig.deviceId;
  if (!deviceSerial) throw new Error("No device selected");

  return new Promise((resolve, reject) => {
    const client = new net.Socket();
    client.setTimeout(timeout);

    let phase: 'transport' | 'shell' | 'reading' = 'transport';
    let data = "";
    const transportCmd = `host:transport:${deviceSerial}`;

    client.connect(adbConfig.port, adbConfig.host, () => {
      const payload = transportCmd.length.toString(16).padStart(4, "0") + transportCmd;
      client.write(payload);
    });

    client.on("data", chunk => {
      const str = chunk.toString();
      if (phase === 'transport') {
        if (str.startsWith('OKAY')) {
          phase = 'shell';
          const shellCmd = `shell:${command}`;
          const payload = shellCmd.length.toString(16).padStart(4, "0") + shellCmd;
          client.write(payload);
        } else if (str.startsWith('FAIL')) {
          client.destroy();
          reject(new Error("Transport failed: " + str.substring(8)));
        }
      } else if (phase === 'shell') {
        if (str.startsWith('OKAY')) {
          phase = 'reading';
          data = str.substring(4);
        } else if (str.startsWith('FAIL')) {
          client.destroy();
          reject(new Error("Shell failed: " + str.substring(8)));
        } else {
          data += str;
        }
      } else {
        data += str;
      }
    });

    client.on("close", () => resolve(data));
    client.on("error", reject);
    client.on("timeout", () => {
      client.destroy();
      reject(new Error("Shell timeout"));
    });
  });
}

async function adbShellRoot(command: string, timeout = 15000): Promise<string> {
  const escapedCommand = escapeShellArg(command);
  const rootCommand = `su -c "${escapedCommand}"`;
  return adbShell(rootCommand, timeout);
}

async function adbShellWithFallback(command: string, timeout = 15000): Promise<{ output: string; isRoot: boolean }> {
  try {
    const output = await adbShellRoot(command, timeout);
    if (output.includes("su: not found") || output.includes("Permission denied") || output.includes("not allowed")) {
      const normalOutput = await adbShell(command, timeout);
      return { output: normalOutput, isRoot: false };
    }
    return { output, isRoot: true };
  } catch {
    const output = await adbShell(command, timeout);
    return { output, isRoot: false };
  }
}

function getAdbCommand(): string {
  const serial = adbConfig.deviceId;
  return serial ? `adb -s ${serial}` : 'adb';
}

async function adbExec(command: string, timeout = 60000): Promise<{ stdout: string; stderr: string }> {
  const adbCmd = getAdbCommand();
  return execAsync(`${adbCmd} ${command}`, { timeout });
}

// ==================== ROUTES ====================

router.post("/wireless-connect", async (req, res) => {
  const { ip, port = 5555 } = req.body;

  if (!ip) {
    return res.status(400).json({ error: "IP address required" });
  }

  if (!isValidIp(ip)) {
    return res.status(400).json({ error: "Invalid IP address" });
  }

  const parts = ip.split('.').map(Number);
  if (parts[0] === 127 || ip === '169.254.169.254') {
    return res.status(400).json({ error: "IP address not allowed" });
  }

  const portNum = parseInt(String(port));
  if (!isValidPort(portNum)) {
    return res.status(400).json({ error: "Invalid port" });
  }

  const target = `${ip}:${portNum}`;

  try {
    console.log(`[ADB] Connecting to ${target}...`);

    const { stdout, stderr } = await execAsync(`adb connect ${target}`, { timeout: 10000 });
    const output = stdout + stderr;

    const success = output.includes("connected") && !output.includes("failed");

    if (success) {
      adbConfig.deviceId = target;
      adbConfig.wireless = true;

      console.log(`[ADB] Connected to ${target}`);

      res.json({
        success: true,
        deviceId: target,
        message: `Connected to ${target}`,
        output: output.trim()
      });
    } else {
      console.error(`[ADB] Failed to connect: ${output}`);
      res.json({
        success: false,
        error: output.trim() || "Connection failed"
      });
    }
  } catch (e: any) {
    console.error("[ADB] Wireless connect error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

router.post("/wireless-disconnect", async (req, res) => {
  const { ip, port = 5555 } = req.body;

  let target: string;

  if (ip) {
    if (!isValidIp(ip)) {
      return res.status(400).json({ error: "Invalid IP address" });
    }
    const portNum = parseInt(String(port));
    if (!isValidPort(portNum)) {
      return res.status(400).json({ error: "Invalid port" });
    }
    target = `${ip}:${portNum}`;
  } else {
    target = adbConfig.deviceId;
  }

  if (!target) {
    return res.status(400).json({ error: "No device to disconnect" });
  }

  if (!isValidDeviceId(target)) {
    return res.status(400).json({ error: "Invalid device target" });
  }

  try {
    const { stdout, stderr } = await execAsync(`adb disconnect ${target}`, { timeout: 5000 });

    if (adbConfig.deviceId === target) {
      adbConfig.deviceId = "";
      adbConfig.wireless = false;
    }

    res.json({
      success: true,
      message: `Disconnected from ${target}`,
      output: (stdout + stderr).trim()
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/adb-toggle', async (req, res) => {
  const { running } = req.body;

  if (typeof running !== 'boolean') {
    return res.status(400).json({ error: 'Missing or invalid "running" parameter' });
  }

  try {
    if (running) {
      exec('adb start-server', (err, stdout, stderr) => {
        if (err) {
          console.error('ADB start error:', stderr || err.message);
          return res.status(500).json({ error: 'Failed to start ADB' });
        }
        return res.json({ success: true, running: true });
      });
    } else {
      exec('adb kill-server', (err, stdout, stderr) => {
        if (err) {
          console.error('ADB kill error:', stderr || err.message);
          return res.status(500).json({ error: 'Failed to stop ADB' });
        }
        return res.json({ success: true, running: false });
      });
    }
  } catch (e: any) {
    console.error('ADB toggle error', e);
    res.status(500).json({ error: e.message });
  }
});

router.get("/config", (_, res) => {
  res.json(adbConfig);
});

router.post("/config", (req, res) => {

  const { host, port, deviceId, wireless, autoConnect, useHostADB } = req.body;

  if (host !== undefined) {
    const allowedHosts = ["127.0.0.1", "host.docker.internal"];
    if (!allowedHosts.includes(host)) {
      return res.status(400).json({ error: "Invalid host" });
    }
    adbConfig.host = host;
  }

  if (port !== undefined) {
    const portNum = parseInt(String(port));
    if (!isValidPort(portNum)) {
      return res.status(400).json({ error: "Invalid port" });
    }
    adbConfig.port = portNum;
  }

  if (deviceId !== undefined) {
    if (deviceId !== "" && !isValidDeviceId(deviceId)) {
      return res.status(400).json({ error: "Invalid deviceId" });
    }
    adbConfig.deviceId = deviceId;
  }

  if (wireless !== undefined) adbConfig.wireless = Boolean(wireless);
  if (autoConnect !== undefined) adbConfig.autoConnect = Boolean(autoConnect);
  if (useHostADB !== undefined) adbConfig.useHostADB = Boolean(useHostADB);

  res.json({ success: true });
});

router.get("/devices", async (_, res) => {
  try {
    const raw = await adbQuery("host:devices-l");
    const parsed = parseAdbResponse(raw);

    if (!parsed.success) {
      return res.status(500).json({ error: parsed.data });
    }

    const lines = parsed.data.split("\n").filter(l => l.trim());

    const devices = lines.map(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 2) return null;

      const id = parts[0];
      const status = parts[1];

      if (!id || id === 'List' || status === 'of') return null;

      let model = "";
      let product = "";
      let device = "";

      for (const part of parts.slice(2)) {
        if (part.startsWith("model:")) model = part.split(":")[1] || "";
        if (part.startsWith("product:")) product = part.split(":")[1] || "";
        if (part.startsWith("device:")) device = part.split(":")[1] || "";
      }

      return {
        id,
        status,
        model: model || device || product || "Unknown",
        product
      };
    }).filter(Boolean);

    res.json(devices);
  } catch (e: any) {
    console.error("ADB devices error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

router.post("/connect", async (_, res) => {
  try {
    const raw = await adbQuery("host:devices");
    const parsed = parseAdbResponse(raw);

    if (!parsed.success) {
      return res.json({ connected: false, error: parsed.data });
    }

    const lines = parsed.data.split("\n").filter(l => l.trim());

    if (adbConfig.deviceId) {
      const deviceConnected = lines.some(line => {
        const parts = line.trim().split(/\s+/);
        return parts[0] === adbConfig.deviceId && parts[1] === "device";
      });
      return res.json({ connected: deviceConnected });
    }

    const hasConnectedDevice = lines.some(line => {
      const parts = line.trim().split(/\s+/);
      return parts.length >= 2 && parts[1] === "device";
    });

    res.json({ connected: hasConnectedDevice });
  } catch (e: any) {
    console.error("ADB connect error:", e.message);
    res.json({ connected: false, error: e.message });
  }
});

router.get("/device-info", async (_, res) => {
  try {
    if (!adbConfig.deviceId) {
      return res.json({ connected: false, error: "No device configured" });
    }

    const devicesRaw = await adbQuery("host:devices");
    const parsed = parseAdbResponse(devicesRaw);

    if (!parsed.success) {
      return res.json({ connected: false, error: parsed.data });
    }

    const lines = parsed.data.split("\n").filter(l => l.trim());
    const deviceLine = lines.find(line => {
      const parts = line.trim().split(/\s+/);
      return parts[0] === adbConfig.deviceId;
    });

    if (!deviceLine) {
      return res.json({ connected: false, error: "Device not found" });
    }

    const parts = deviceLine.trim().split(/\s+/);
    const status = parts[1];

    if (status !== "device") {
      return res.json({
        connected: false,
        error: `Device status: ${status}`,
        id: adbConfig.deviceId,
        status
      });
    }

    let isRooted = false;
    try {
      const whoami = await adbShellRoot("whoami");
      isRooted = whoami.trim() === "root";
    } catch {
      isRooted = false;
    }

    try {
      const [modelResult, versionResult, sdkResult] = await Promise.all([
        adbShell("getprop ro.product.model").catch(() => "Unknown"),
        adbShell("getprop ro.build.version.release").catch(() => "?"),
        adbShell("getprop ro.build.version.sdk").catch(() => "?"),
      ]);

      res.json({
        connected: true,
        id: adbConfig.deviceId,
        status: "device",
        model: modelResult.trim(),
        android_version: versionResult.trim(),
        sdk: sdkResult.trim(),
        isRooted
      });
    } catch (shellError: any) {
      res.json({
        connected: true,
        id: adbConfig.deviceId,
        status: "device",
        model: "Unknown",
        android_version: "?",
        sdk: "?",
        isRooted,
        warning: "Could not get device properties"
      });
    }
  } catch (e: any) {
    console.error("ADB device-info error:", e.message);
    res.json({ connected: false, error: e.message });
  }
});

router.get("/packages", async (req, res) => {
  try {
    const includeSystem = req.query.includeSystem === 'true';
    const cmd = includeSystem ? "pm list packages -f" : "pm list packages -f -3";
    const raw = await adbShell(cmd);

    const packages = raw.split("\n")
      .filter(l => l.startsWith("package:"))
      .map(line => {
        const match = line.match(/package:(.+)=(.+)/);
        if (match) {
          const apkPath = match[1];
          const name = match[2].trim();
          const isSystem = apkPath.includes("/system/") || apkPath.includes("/product/");
          return { name, path: apkPath, isSystem };
        }
        return null;
      })
      .filter(Boolean)
      .sort((a: any, b: any) => a.name.localeCompare(b.name));

    res.json(packages);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== INSTALL APK ====================
const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.originalname.toLowerCase().endsWith('.apk') ||
        file.mimetype === 'application/vnd.android.package-archive') {
      cb(null, true);
    } else {
      cb(new Error('Only APK files are allowed'));
    }
  }
});

router.post("/install", upload.single("apk"), async (req: Request, res: Response) => {
  const file = req.file;

  if (!file) {
    return res.status(400).json({ error: "No APK file provided" });
  }

  const safeName = sanitizeFilename(path.basename(file.originalname));
  if (!safeName.toLowerCase().endsWith('.apk')) {
    return res.status(400).json({ error: "Invalid file name" });
  }

  const apkPath = path.join(TMP_DIR, safeName);

  if (!path.resolve(apkPath).startsWith(path.resolve(TMP_DIR) + path.sep)) {
    return res.status(400).json({ error: "Invalid file path" });
  }

  try {
    fs.renameSync(file.path, apkPath);

    if (!adbConfig.deviceId) {
      throw new Error("No device selected");
    }

    console.log(`[ADB] Installing APK: ${safeName} (${(file.size / 1024 / 1024).toFixed(2)} MB)`);

    const { stdout, stderr } = await adbExec(`install -r "${apkPath}"`, 180000);

    const output = stdout + stderr;
    const success = output.toLowerCase().includes("success");

    if (success) {
      console.log(`[ADB] APK installed successfully: ${safeName}`);
      res.json({
        success: true,
        message: "APK installed successfully",
        filename: safeName,
        output: output.trim()
      });
    } else {
      console.error(`[ADB] APK installation failed: ${output}`);
      res.json({
        success: false,
        error: output.trim() || "Installation failed",
        filename: safeName
      });
    }
  } catch (e: any) {
    console.error("[ADB] Install error:", e.message);
    res.status(500).json({
      error: e.message,
      details: "Make sure ADB is running and device is connected"
    });
  } finally {
    try {
      if (fs.existsSync(apkPath)) {
        fs.unlinkSync(apkPath);
        console.log(`[ADB] Cleaned up: ${apkPath}`);
      }
      if (fs.existsSync(file.path)) {
        fs.unlinkSync(file.path);
      }
    } catch (cleanupErr) {
      console.error("[ADB] Cleanup error:", cleanupErr);
    }
  }
});

router.post("/uninstall", async (req, res) => {
  try {
    const { package: pkg } = req.body;
    if (!pkg) {
      return res.status(400).json({ error: "Package name required" });
    }

    if (!isValidPackageName(pkg)) {
      return res.status(400).json({ error: "Invalid package name" });
    }

    const result = await adbShell(`pm uninstall ${pkg}`);
    const success = result.toLowerCase().includes("success");

    res.json({ success, output: result.trim(), error: success ? null : result.trim() });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== EXTRACT APK ====================
router.post("/extract", async (req, res) => {
  const { package: pkg } = req.body;

  if (!pkg) {
    return res.status(400).json({ error: "Package name required" });
  }

  if (!isValidPackageName(pkg)) {
    return res.status(400).json({ error: "Invalid package name" });
  }

  const workDir = path.join(TMP_DIR, `extract_${Date.now()}`);

  try {
    if (!adbConfig.deviceId) {
      throw new Error("No device selected");
    }

    fs.mkdirSync(workDir, { recursive: true });
    fs.mkdirSync(EXTRACTED_DIR, { recursive: true });

    console.log(`[ADB] Extracting APK for package: ${pkg}`);

    const pathResult = await adbShell(`pm path ${pkg}`);
    const apkPaths = pathResult.split("\n")
      .filter(l => l.startsWith("package:"))
      .map(l => l.replace("package:", "").trim());

    if (apkPaths.length === 0) {
      throw new Error("Package not found");
    }

    for (const p of apkPaths) {
      if (!isValidDevicePath(p)) {
        throw new Error(`Invalid APK path returned by device: ${p}`);
      }
    }

    const isSplit = apkPaths.length > 1;
    const safePkgName = sanitizeFilename(pkg);

    console.log(`[ADB] Found ${apkPaths.length} APK(s) for ${pkg}`);

    const pulledFiles: string[] = [];
    for (let i = 0; i < apkPaths.length; i++) {
      const apkPath = apkPaths[i];
      const fileName = isSplit ? `${safePkgName}_part${i + 1}.apk` : `${safePkgName}.apk`;
      const localPath = path.join(workDir, fileName);

      if (!path.resolve(localPath).startsWith(path.resolve(workDir) + path.sep)) {
        throw new Error("Invalid output path");
      }

      console.log(`[ADB] Pulling: ${apkPath} -> ${localPath}`);

      await adbExec(`pull "${apkPath}" "${localPath}"`, 120000);

      if (fs.existsSync(localPath)) {
        pulledFiles.push(localPath);
      } else {
        throw new Error(`Failed to pull: ${apkPath}`);
      }
    }

    let finalApkPath: string;
    let finalApkName: string;

    if (isSplit) {
      console.log(`[ADB] Merging ${pulledFiles.length} split APKs...`);

      finalApkName = `${safePkgName}_merged.apk`;
      finalApkPath = path.join(EXTRACTED_DIR, finalApkName);
      if (!path.resolve(finalApkPath).startsWith(path.resolve(EXTRACTED_DIR) + path.sep)) {
        throw new Error("Invalid output path");
      }

      if (!fs.existsSync(APK_EDITOR_PATH)) {
        throw new Error(`APKEditor not found at ${APK_EDITOR_PATH}`);
      }

      const mergeCmd = `java -jar "${APK_EDITOR_PATH}" m -i "${workDir}" -o "${finalApkPath}"`;

      console.log(`[ADB] Running: ${mergeCmd}`);

      const { stdout, stderr } = await execAsync(mergeCmd, { timeout: 300000 });

      console.log(`[ADB] APKEditor output: ${stdout}`);
      if (stderr) console.log(`[ADB] APKEditor stderr: ${stderr}`);

      if (!fs.existsSync(finalApkPath)) {
        throw new Error("Merge failed - output file not created");
      }

      console.log(`[ADB] Merge successful: ${finalApkPath}`);
    } else {
      finalApkName = `${safePkgName}.apk`;
      finalApkPath = path.join(EXTRACTED_DIR, finalApkName);

      if (!path.resolve(finalApkPath).startsWith(path.resolve(EXTRACTED_DIR) + path.sep)) {
        throw new Error("Invalid output path");
      }

      fs.copyFileSync(pulledFiles[0], finalApkPath);
      console.log(`[ADB] Single APK copied to: ${finalApkPath}`);
    }

    const stats = fs.statSync(finalApkPath);
    const fileSizeMB = (stats.size / 1024 / 1024).toFixed(2);

    res.json({
      success: true,
      package: pkg,
      isSplit,
      originalCount: apkPaths.length,
      outputFile: finalApkName,
      outputPath: `/api/v1/adb/download/${finalApkName}`,
      downloadUrl: `/api/v1/adb/download/${finalApkName}`,
      size: stats.size,
      sizeMB: fileSizeMB,
      message: isSplit
        ? `Merged ${apkPaths.length} split APKs into single APK (${fileSizeMB} MB)`
        : `Extracted APK (${fileSizeMB} MB)`
    });

  } catch (e: any) {
    console.error("[ADB] Extract error:", e.message);
    res.status(500).json({
      success: false,
      error: e.message,
      package: pkg
    });
  } finally {
    try {
      if (fs.existsSync(workDir)) {
        fs.rmSync(workDir, { recursive: true, force: true });
        console.log(`[ADB] Cleaned up work dir: ${workDir}`);
      }
    } catch (cleanupErr) {
      console.error("[ADB] Cleanup error:", cleanupErr);
    }
  }
});

// ==================== DOWNLOAD EXTRACTED APK ====================
router.get("/download/:filename", (req, res) => {
  try {
    const filename = req.params.filename;

    const safeName = sanitizeFilename(path.basename(filename));

    if (!safeName || !safeName.endsWith('.apk')) {
      return res.status(400).json({ error: "Invalid filename" });
    }

    const filePath = path.join(EXTRACTED_DIR, safeName);

    const resolvedPath = path.resolve(filePath);
    const resolvedDir = path.resolve(EXTRACTED_DIR);
    if (!resolvedPath.startsWith(resolvedDir + path.sep)) {
      return res.status(400).json({ error: "Invalid filename" });
    }

    console.log(`[ADB] Download request: ${safeName}`);

    if (!fs.existsSync(resolvedPath)) {
      console.log(`[ADB] File not found: ${resolvedPath}`);
      return res.status(404).json({ error: "File not found" });
    }

    const stats = fs.statSync(resolvedPath);
    console.log(`[ADB] Serving file: ${resolvedPath} (${(stats.size / 1024 / 1024).toFixed(2)} MB)`);

    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
    res.setHeader('Content-Length', stats.size);

    const stream = fs.createReadStream(resolvedPath);
    stream.pipe(res);

    stream.on('error', (err) => {
      console.error('[ADB] Stream error:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: "Error reading file" });
      }
    });

  } catch (e: any) {
    console.error('[ADB] Download error:', e);
    res.status(500).json({ error: e.message });
  }
});

router.get("/extracted", (_, res) => {
  try {
    if (!fs.existsSync(EXTRACTED_DIR)) {
      return res.json({ files: [] });
    }

    const files = fs.readdirSync(EXTRACTED_DIR)
      .filter(f => f.endsWith('.apk'))
      .map(f => {
        const filePath = path.join(EXTRACTED_DIR, f);
        const stats = fs.statSync(filePath);
        return {
          name: f,
          size: stats.size,
          sizeMB: (stats.size / 1024 / 1024).toFixed(2),
          downloadUrl: `/api/v1/adb/download/${f}`,
          created: stats.birthtime
        };
      })
      .sort((a, b) => new Date(b.created).getTime() - new Date(a.created).getTime());

    res.json({ files });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.delete("/extracted/:filename", (req, res) => {
  try {
    const filename = req.params.filename;

    const safeName = sanitizeFilename(path.basename(filename));

    if (!safeName || !safeName.endsWith('.apk')) {
      return res.status(400).json({ error: "Invalid filename" });
    }

    const resolvedPath = path.resolve(path.join(EXTRACTED_DIR, safeName));
    const resolvedDir = path.resolve(EXTRACTED_DIR);

    if (!resolvedPath.startsWith(resolvedDir + path.sep)) {
      return res.status(400).json({ error: "Invalid filename" });
    }

    if (!fs.existsSync(resolvedPath)) {
      return res.status(404).json({ error: "File not found" });
    }

    fs.unlinkSync(resolvedPath);
    console.log(`[ADB] Deleted extracted APK: ${safeName}`);

    res.json({ success: true, deleted: safeName });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== FILE OPERATIONS ====================

router.get("/ls", async (req, res) => {
  try {
    const dirPath = (req.query.path as string) || "/data/data";
    const useRoot = req.query.root !== 'false';

    if (!isValidDevicePath(dirPath)) {
      return res.status(400).json({ error: "Invalid path" });
    }

    let raw: string;
    let isRoot = false;

    if (useRoot) {
      const result = await adbShellWithFallback(`ls -la "${escapeShellArg(dirPath)}"`);
      raw = result.output;
      isRoot = result.isRoot;
    } else {
      raw = await adbShell(`ls -la "${escapeShellArg(dirPath)}" 2>/dev/null || ls -l "${escapeShellArg(dirPath)}"`);
    }

    if (raw.includes("Permission denied") || raw.includes("No such file")) {
      return res.json({
        files: [],
        error: raw.trim(),
        isRoot,
        path: dirPath
      });
    }

    const files = raw.split("\n")
      .filter(l => l.trim() && !l.startsWith("total"))
      .map(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 4) return null;

        const permissions = parts[0];
        let name: string;
        let size: string;

        if (parts.length >= 8) {
          size = parts[4];
          name = parts.slice(7).join(" ");
        } else if (parts.length >= 5) {
          size = parts[3];
          name = parts.slice(4).join(" ");
        } else {
          return null;
        }

        if (name.includes(" -> ")) {
          name = name.split(" -> ")[0];
        }

        if (!name || name === "." || name === "..") return null;

        const type = permissions.startsWith("d") ? "directory" :
                     permissions.startsWith("l") ? "symlink" : "file";

        const fullPath = dirPath.endsWith("/")
          ? `${dirPath}${name}`
          : `${dirPath}/${name}`;

        return { name, type, size, permissions, path: fullPath };
      })
      .filter(Boolean);

    res.json({ files, isRoot, path: dirPath });
  } catch (e: any) {
    res.status(500).json({ error: e.message, files: [] });
  }
});

router.get("/cat", async (req, res) => {
  try {
    const filePath = req.query.path as string;
    if (!filePath) {
      return res.status(400).json({ error: "File path required" });
    }

    if (!isValidDevicePath(filePath)) {
      return res.status(400).json({ error: "Invalid path" });
    }

    const maxSize = parseInt(req.query.maxSize as string) || 100000;

    const escaped = escapeShellArg(filePath);
    const sizeResult = await adbShellWithFallback(`stat -c%s "${escaped}" 2>/dev/null || wc -c < "${escaped}"`);
    const fileSize = parseInt(sizeResult.output.trim()) || 0;

    if (fileSize > maxSize) {
      return res.json({
        error: `File too large (${fileSize} bytes). Max: ${maxSize} bytes`,
        size: fileSize,
        truncated: true
      });
    }

    const result = await adbShellWithFallback(`cat "${escaped}"`);

    res.json({
      content: result.output,
      isRoot: result.isRoot,
      size: fileSize
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get("/pull", async (req, res) => {
  try {
    const filePath = req.query.path as string;
    if (!filePath) {
      return res.status(400).json({ error: "File path required" });
    }

    if (!isValidDevicePath(filePath)) {
      return res.status(400).json({ error: "Invalid path" });
    }

    const maxSize = 5 * 1024 * 1024;

    const escaped = escapeShellArg(filePath);
    const sizeResult = await adbShellWithFallback(`stat -c%s "${escaped}" 2>/dev/null`);
    const fileSize = parseInt(sizeResult.output.trim()) || 0;

    if (fileSize > maxSize) {
      return res.json({
        success: false,
        error: `File too large (${(fileSize / 1024 / 1024).toFixed(2)} MB). Use adb pull command.`,
        command: `adb pull "${filePath}"`,
        size: fileSize
      });
    }

    const result = await adbShellWithFallback(`base64 "${escaped}"`);

    if (result.output.includes("No such file") || result.output.includes("Permission denied")) {
      return res.json({
        success: false,
        error: result.output.trim()
      });
    }

    res.json({
      success: true,
      content: result.output.replace(/\s/g, ''),
      encoding: 'base64',
      isRoot: result.isRoot,
      size: fileSize
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/rm", async (req, res) => {
  try {
    const { path: filePath } = req.body;
    if (!filePath) {
      return res.status(400).json({ error: "Path required" });
    }

    if (!isValidDevicePath(filePath)) {
      return res.status(400).json({ error: "Invalid path" });
    }

    const blocked = ["/data/data", "/data", "/system", "/sdcard", "/", "/data/app"];
    if (blocked.includes(filePath) || blocked.includes(filePath.replace(/\/$/, ''))) {
      return res.status(403).json({ error: "Cannot delete this path" });
    }

    const result = await adbShellWithFallback(`rm -rf "${escapeShellArg(filePath)}"`);

    res.json({
      success: !result.output.includes("Permission denied") && !result.output.includes("No such file"),
      output: result.output,
      isRoot: result.isRoot
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/cp", async (req, res) => {
  try {
    const { source, destination } = req.body;
    if (!source || !destination) {
      return res.status(400).json({ error: "Source and destination required" });
    }

    if (!isValidDevicePath(source) || !isValidDevicePath(destination)) {
      return res.status(400).json({ error: "Invalid path" });
    }

    const result = await adbShellWithFallback(`cp -r "${escapeShellArg(source)}" "${escapeShellArg(destination)}"`);

    res.json({
      success: !result.output.includes("Permission denied") && !result.output.includes("No such file"),
      output: result.output,
      isRoot: result.isRoot
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/shell", async (req, res) => {
  try {
    const { command, root = false } = req.body;
    if (!command) {
      return res.status(400).json({ error: "Command required" });
    }

    if (typeof command !== 'string' || command.length > 1024) {
      return res.status(400).json({ error: "Invalid or too long command" });
    }

    const blocked = [
      "rm -rf /", "reboot", "shutdown", "format", "mkfs", "dd if=",
      "wget ", "curl ", "nc ", "netcat", "bash -i", "sh -i",
      "> /dev/", "chmod 777 /", "chown root"
    ];
    if (blocked.some(b => command.toLowerCase().includes(b))) {
      return res.status(403).json({ error: "Command blocked for safety" });
    }

    let output: string;
    let isRoot = false;

    if (root) {
      const result = await adbShellWithFallback(command);
      output = result.output;
      isRoot = result.isRoot;
    } else {
      output = await adbShell(command);
    }

    res.json({ output: output.trim(), isRoot });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/datadir", async (req, res) => {
  try {
    const { package: pkg } = req.body;
    if (!pkg) {
      return res.status(400).json({ error: "Package name required" });
    }

    if (!isValidPackageName(pkg)) {
      return res.status(400).json({ error: "Invalid package name" });
    }

    const dataPath = `/data/data/${pkg}`;
    const result = await adbShellWithFallback(`ls "${escapeShellArg(dataPath)}"`);

    const accessible = !result.output.includes("Permission denied") &&
                       !result.output.includes("No such file");

    res.json({
      success: accessible,
      path: dataPath,
      accessible,
      isRoot: result.isRoot,
      contents: accessible ? result.output.trim() : null,
      error: accessible ? null : result.output.trim()
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== LOGCAT ====================

let logcatProcess: any = null;
let logcatBuffer: string[] = [];
const MAX_LOGCAT_LINES = 1000;

router.post("/logcat/start", async (req, res) => {
  const { package: pkg, level = 'V' } = req.body;

  if (!pkg) {
    return res.status(400).json({ error: "Package name required" });
  }

  if (!isValidPackageName(pkg)) {
    return res.status(400).json({ error: "Invalid package name" });
  }

  const validLevels = ['V', 'D', 'I', 'W', 'E', 'F', 'S'];
  if (!validLevels.includes(String(level).toUpperCase())) {
    return res.status(400).json({ error: "Invalid log level" });
  }
  const safeLevel = String(level).toUpperCase();

  if (!adbConfig.deviceId) {
    return res.status(400).json({ error: "No device selected" });
  }

  if (logcatProcess) {
    try { logcatProcess.kill(); } catch {}
    logcatProcess = null;
  }

  logcatBuffer = [];

  try {
    const pidResult = await adbShell(`pidof ${pkg}`);
    const pid = pidResult.trim();

    if (!pid || !/^\d+$/.test(pid)) {
      return res.status(400).json({
        error: "Package not running",
        suggestion: "Open the app on the device first"
      });
    }

    const { spawn } = require('child_process');

    logcatProcess = spawn('adb', [
      '-s', adbConfig.deviceId,
      'logcat',
      '-v', 'time',
      '--pid', pid,
      `*:${safeLevel}`
    ]);

    logcatProcess.stdout.on('data', (data: Buffer) => {
      const lines = data.toString().split('\n').filter((l: string) => l.trim());
      for (const line of lines) {
        logcatBuffer.push(line);
        if (logcatBuffer.length > MAX_LOGCAT_LINES) {
          logcatBuffer.shift();
        }
      }
    });

    logcatProcess.on('close', () => {
      logcatProcess = null;
    });

    res.json({
      success: true,
      package: pkg,
      pid,
      message: `Logcat started for ${pkg}`
    });

  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/logcat/stop", (req, res) => {
  if (logcatProcess) {
    try {
      logcatProcess.kill();
      logcatProcess = null;
      res.json({ success: true, message: "Logcat stopped" });
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  } else {
    res.json({ success: true, message: "Logcat was not running" });
  }
});

router.get("/logcat/logs", (req, res) => {
  const { since = 0, filter = '' } = req.query;
  const sinceIndex = parseInt(since as string) || 0;

  const filterStr = String(filter).substring(0, 256);

  let logs = logcatBuffer.slice(sinceIndex);

  if (filterStr) {
    const filterLower = filterStr.toLowerCase();
    logs = logs.filter(l => l.toLowerCase().includes(filterLower));
  }

  res.json({
    running: logcatProcess !== null,
    total: logcatBuffer.length,
    logs,
    newIndex: logcatBuffer.length
  });
});

router.post("/logcat/clear", (req, res) => {
  logcatBuffer = [];
  res.json({ success: true, message: "Buffer cleared" });
});

router.get("/logcat/status", (req, res) => {
  res.json({
    running: logcatProcess !== null,
    bufferSize: logcatBuffer.length
  });
});

router.get("/check-root", async (_, res) => {
  try {
    const result = await adbShellRoot("id");
    const isRoot = result.includes("uid=0") || result.includes("root");

    res.json({
      isRoot,
      output: result.trim()
    });
  } catch (e: any) {
    res.json({
      isRoot: false,
      error: e.message
    });
  }
});

export default router;
