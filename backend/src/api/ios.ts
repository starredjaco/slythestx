import { Router } from 'express';
import { execSync, spawn, ChildProcess } from 'child_process';
import { Client, ClientChannel } from 'ssh2';
import Redis from 'ioredis';
import fs from 'fs';
import path from 'path';

const router = Router();

const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  retryStrategy: (times) => Math.min(times * 50, 5000),
});

redis.on('error', (err) => console.error('Redis error:', err));
redis.on('connect', () => console.log('Redis connected'));

const CACHE_TTL = {
  DEVICE_INFO: 3000,      
  APPS_LIST: 1200,        
  APP_DETAILS: 1800,      
  FILE_LIST: 600,         
  FILE_CONTENT: 3000,    
  BINARIES: 6000,         
};

function cacheKey(type: string, ...parts: string[]): string {
  const host = iosConfig.sshHost || iosConfig.udid || 'unknown';
  return `ios:${host}:${type}:${parts.join(':')}`;
}

async function cachedSSH<T>(
  key: string, 
  ttl: number, 
  fetcher: () => Promise<T>,
  forceRefresh = false
): Promise<T> {
  if (!forceRefresh) {
    try {
      const cached = await redis.get(key);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch {}
  }

  const result = await fetcher();
  
  try {
    await redis.setex(key, ttl, JSON.stringify(result));
  } catch {}

  return result;
}

async function invalidateCache(pattern: string): Promise<void> {
  try {
    const keys = await redis.keys(pattern);
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } catch (e) {
    console.error('Cache invalidation error:', e);
  }
}

async function invalidateDeviceCache(): Promise<void> {
  const host = iosConfig.sshHost || iosConfig.udid || 'unknown';
  await invalidateCache(`ios:${host}:*`);
}

// ==================== INTERFACES ====================

interface IOSDevice {
  udid: string;
  name: string;
  model: string;
  version: string;
  jailbroken: boolean;
  connected: boolean;
  connectionType: 'usb' | 'ssh';
}

interface IOSConfig {
  udid: string | null;
  connectionType: 'usb' | 'ssh';
  sshHost: string;
  sshPort: number;
  sshUser: string;
  sshPassword: string;
  jailbroken: boolean;
  rootless: boolean;
  deviceInfo: {
    name: string;
    model: string;
    version: string;
    jailbreakType?: string;
  } | null;
}

interface AppInfo {
  bundleId: string;
  name: string;
  version: string;
  type: string;
}

interface AppDetails {
  bundleId: string;
  name: string;
  version: string;
  bundlePath: string;
  dataPath: string;
  paths: {
    bundle: string;
    data: string;
    documents: string;
    library: string;
    caches: string;
    preferences: string;
  };
}

let iosConfig: IOSConfig = {
  udid: null,
  connectionType: 'usb',
  sshHost: '',
  sshPort: 22,
  sshUser: 'mobile',
  sshPassword: '',
  jailbroken: false,
  rootless: false,
  deviceInfo: null,
};

let syslogProcess: ChildProcess | null = null;
let syslogBuffer: string[] = [];

// ==================== HELPERS ====================

function execCommand(cmd: string, timeout = 30000): string {
  try {
    return execSync(cmd, { timeout, encoding: 'utf-8' }).trim();
  } catch (e: any) {
    return e.stdout?.toString() || e.message || '';
  }
}

async function sshCommand(command: string, useSudo = false): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!iosConfig.sshHost) {
      return reject(new Error('SSH host not configured'));
    }

    const conn = new Client();
    let output = '';

    let finalCommand = command;
    if (useSudo && iosConfig.sshUser !== 'root') {
      finalCommand = `echo '${iosConfig.sshPassword}' | sudo -S ${command}`;
    }

    conn.on('ready', () => {
      conn.exec(finalCommand, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          conn.end();
          return reject(err);
        }

        stream.on('data', (data: Buffer) => {
          output += data.toString();
        });

        stream.stderr.on('data', (data: Buffer) => {
        
          const text = data.toString();
          if (!text.includes('Password:') && !text.includes('[sudo]')) {
            output += text;
          }
        });

        stream.on('close', () => {
          conn.end();
          resolve(output.trim());
        });
      });
    });

    conn.on('error', (err: Error) => reject(err));

    conn.connect({
      host: iosConfig.sshHost,
      port: iosConfig.sshPort,
      username: iosConfig.sshUser,
      password: iosConfig.sshPassword,
      readyTimeout: 10000,
    });
  });
}

async function sshRoot(command: string): Promise<string> {
  return sshCommand(command, true);
}

// ==================== DEVICES ====================

router.get('/devices', (req, res) => {
  const devices: IOSDevice[] = [];

  try {
    const output = execCommand('idevice_id -l');
    if (output && !output.includes('ERROR') && !output.includes('No device')) {
      const udids = output.split('\n').filter(u => u.trim() && u.length > 10);

      for (const udid of udids) {
        try {
          const name = execCommand(`ideviceinfo -u ${udid} -k DeviceName`);
          const model = execCommand(`ideviceinfo -u ${udid} -k ProductType`);
          const version = execCommand(`ideviceinfo -u ${udid} -k ProductVersion`);

          if (name && !name.includes('ERROR')) {
            devices.push({
              udid,
              name,
              model,
              version,
              jailbroken: false,
              connected: true,
              connectionType: 'usb',
            });
          }
        } catch {}
      }
    }
  } catch {}

  if (iosConfig.connectionType === 'ssh' && iosConfig.jailbroken && iosConfig.deviceInfo) {
    devices.push({
      udid: `ssh-${iosConfig.sshHost}`,
      name: iosConfig.deviceInfo.name || `SSH: ${iosConfig.sshHost}`,
      model: iosConfig.deviceInfo.model || 'Unknown',
      version: iosConfig.deviceInfo.version || 'Unknown',
      jailbroken: true,
      connected: true,
      connectionType: 'ssh',
    });
  }

  res.json(devices);
});

router.post('/select', (req, res) => {
  const { udid, connectionType } = req.body;
  iosConfig.udid = udid;
  if (connectionType) {
    iosConfig.connectionType = connectionType;
  }
  res.json({ success: true, udid, connectionType: iosConfig.connectionType });
});

router.post('/ssh/config', (req, res) => {
  const { host, port, user, password } = req.body;
  iosConfig.sshHost = host || '';
  iosConfig.sshPort = port || 22;
  iosConfig.sshUser = user || 'mobile';
  iosConfig.sshPassword = password || '';
  res.json({ success: true });
});

router.post('/ssh/connect', async (req, res) => {
  const { host, port, user, password } = req.body;

  if (host) iosConfig.sshHost = host;
  if (port) iosConfig.sshPort = port;
  if (user) iosConfig.sshUser = user;
  if (password) iosConfig.sshPassword = password;

  if (!iosConfig.sshHost) {
    return res.status(400).json({ error: 'SSH host required' });
  }

  try {
    
    const uname = await sshCommand('uname -a');
    
    
    let jailbreakType = 'Unknown';
    let rootless = false;

    try {
      const hasVarJb = await sshCommand('test -d /var/jb && echo "yes" || echo "no"');
      if (hasVarJb.includes('yes')) {
        rootless = true;
        jailbreakType = 'Rootless (Dopamine/Fugu15)';
      } else {
        const hasCheckra1n = await sshCommand('test -f /checkra1n.dmg && echo "yes" || echo "no"');
        if (hasCheckra1n.includes('yes')) {
          jailbreakType = 'checkra1n';
        } else {
          const hasUncOver = await sshCommand('test -f /electra && echo "yes" || echo "no"');
          if (hasUncOver.includes('yes')) {
            jailbreakType = 'unc0ver';
          }
        }
      }
    } catch {}

    let deviceName = 'iOS Device';
    let deviceModel = 'Unknown';
    let deviceVersion = 'Unknown';

    try {
      const versionOutput = await sshCommand('sw_vers -productVersion 2>/dev/null');
      if (versionOutput) deviceVersion = versionOutput;
    } catch {}

    try {
      const modelOutput = await sshCommand('uname -m');
      if (modelOutput) deviceModel = modelOutput;
    } catch {}

    try {
      const hostnameOutput = await sshCommand('hostname');
      if (hostnameOutput) deviceName = hostnameOutput;
    } catch {}

    let hasSudo = false;
    if (iosConfig.sshUser !== 'root') {
      try {
        const sudoTest = await sshRoot('id');
        hasSudo = sudoTest.includes('uid=0');
      } catch {}
    }

    iosConfig.jailbroken = true;
    iosConfig.rootless = rootless;
    iosConfig.connectionType = 'ssh';
    iosConfig.udid = `ssh-${iosConfig.sshHost}`;
    iosConfig.deviceInfo = {
      name: deviceName,
      model: deviceModel,
      version: deviceVersion,
      jailbreakType,
    };

    await invalidateDeviceCache();

    res.json({
      success: true,
      output: uname,
      jailbroken: true,
      rootless,
      jailbreakType,
      hasSudo,
      user: iosConfig.sshUser,
      deviceInfo: iosConfig.deviceInfo,
    });
  } catch (e: any) {
    iosConfig.jailbroken = false;
    iosConfig.deviceInfo = null;
    res.json({ success: false, error: e.message, jailbroken: false });
  }
});

router.post('/ssh/disconnect', async (req, res) => {
  if (iosConfig.connectionType === 'ssh') {
  
    await invalidateDeviceCache();

    iosConfig.jailbroken = false;
    iosConfig.rootless = false;
    iosConfig.udid = null;
    iosConfig.deviceInfo = null;
  }
  res.json({ success: true });
});

router.post('/ssh/test', async (req, res) => {
  try {
    const result = await sshCommand('uname -a');
    iosConfig.jailbroken = true;
    res.json({ success: true, output: result, jailbroken: true });
  } catch (e: any) {
    res.json({ success: false, error: e.message, jailbroken: false });
  }
});

router.post('/ssh/shell', async (req, res) => {
  const { command, asRoot } = req.body;

  if (!command) {
    return res.status(400).json({ error: 'Command required' });
  }

  const blocked = ['rm -rf /', 'rm -rf /*', 'reboot', 'shutdown', 'killall SpringBoard', 'killall backboardd'];
  if (blocked.some(b => command.includes(b))) {
    return res.status(403).json({ error: 'Command blocked for safety' });
  }

  try {
    const output = asRoot ? await sshRoot(command) : await sshCommand(command);
    res.json({ success: true, output });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/info', async (req, res) => {
  const forceRefresh = req.query.refresh === 'true';

  if (iosConfig.connectionType === 'ssh') {
    if (!iosConfig.jailbroken) {
      return res.status(400).json({ error: 'SSH not connected' });
    }

    try {
      const key = cacheKey('info');
      const info = await cachedSSH(key, CACHE_TTL.DEVICE_INFO, async () => {
        const data: Record<string, string> = {};

        data.connection = 'SSH';
        data.host = iosConfig.sshHost;
        data.user = iosConfig.sshUser;
        data.jailbreakType = iosConfig.deviceInfo?.jailbreakType || 'Unknown';
        data.rootless = iosConfig.rootless ? 'Yes' : 'No';

        try { data.hostname = await sshCommand('hostname'); } catch {}
        try { data.version = await sshCommand('sw_vers -productVersion 2>/dev/null'); } catch {}
        try { data.build = await sshCommand('sw_vers -buildVersion 2>/dev/null'); } catch {}
        try { data.kernel = await sshCommand('uname -r'); } catch {}
        try { data.architecture = await sshCommand('uname -m'); } catch {}
        try { data.uptime = await sshCommand('uptime'); } catch {}
        try { data.freeSpace = await sshCommand("df -h / | tail -1 | awk '{print $4}'"); } catch {}

        return data;
      }, forceRefresh);

      res.json(info);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  } else {

    if (!iosConfig.udid) {
      return res.status(400).json({ error: 'No device selected' });
    }

    try {
      const info = {
        connection: 'USB',
        name: execCommand(`ideviceinfo -u ${iosConfig.udid} -k DeviceName`),
        model: execCommand(`ideviceinfo -u ${iosConfig.udid} -k ProductType`),
        version: execCommand(`ideviceinfo -u ${iosConfig.udid} -k ProductVersion`),
        build: execCommand(`ideviceinfo -u ${iosConfig.udid} -k BuildVersion`),
        serial: execCommand(`ideviceinfo -u ${iosConfig.udid} -k SerialNumber`),
        wifi: execCommand(`ideviceinfo -u ${iosConfig.udid} -k WiFiAddress`),
        battery: execCommand(`ideviceinfo -u ${iosConfig.udid} -k BatteryCurrentCapacity`),
      };
      res.json(info);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  }
});

router.get('/apps', async (req, res) => {
  const forceRefresh = req.query.refresh === 'true';

  try {
    if (iosConfig.connectionType === 'ssh') {
      if (!iosConfig.jailbroken) {
        return res.status(400).json({ error: 'SSH not connected' });
      }

      const key = cacheKey('apps', 'list');
      const apps = await cachedSSH<AppInfo[]>(key, CACHE_TTL.APPS_LIST, async () => {
        const plistBuddy = iosConfig.rootless 
          ? '/var/jb/usr/libexec/PlistBuddy' 
          : '/usr/libexec/PlistBuddy';

        const cmd = `
find /var/containers/Bundle/Application -type d -name "*.app" -maxdepth 3 2>/dev/null |
while read app; do
  plist="$app/Info.plist"
  id=$(${plistBuddy} -c "Print CFBundleIdentifier" "$plist" 2>/dev/null | grep -v "Cannot" | head -1)
  [ -z "$id" ] && continue
  ver=$(${plistBuddy} -c "Print CFBundleShortVersionString" "$plist" 2>/dev/null | grep -v "Does Not Exist" | grep -v "Cannot" | head -1)
  name=$(basename "$app" .app)
  echo "$id|$name|$ver"
done
        `.trim();

        const output = await sshCommand(cmd);
        
        return output
          .split('\n')
          .filter(Boolean)
          .map(line => {
            const [bundleId, name, version] = line.split('|');
            return { bundleId, name, version: version || '', type: 'user' };
          })
          .filter(app => app.bundleId)
          .sort((a, b) => a.name.localeCompare(b.name));
      }, forceRefresh);

      return res.json(apps);
    }

    if (!iosConfig.udid) {
      return res.status(400).json({ error: 'No device selected' });
    }

    const output = execCommand(`ideviceinstaller -u ${iosConfig.udid} -l`, 30000);

    if (!output || output.includes('ERROR') || output.includes('No device found')) {
      return res.json([]);
    }

    const lines = output.split('\n');
    const apps: any[] = [];

    for (const line of lines) {
      
      if (!line.trim() || line.startsWith('CFBundleIdentifier')) {
        continue;
      }

      const match = line.match(/^([^,]+),\s*"([^"]*)",\s*"([^"]*)"$/);
      
      if (match) {
        apps.push({
          bundleId: match[1].trim(),
          name: match[3].trim(),
          version: match[2].trim(),
          type: 'user'
        });
      }
    }

    apps.sort((a, b) => a.name.localeCompare(b.name));
    res.json(apps);

  } catch (e: any) {
    console.error('Error in /apps:', e);
    res.status(500).json({ error: e.message });
  }
});

router.get('/apps/:bundleId', async (req, res) => {
  const { bundleId } = req.params;
  const forceRefresh = req.query.refresh === 'true';

  try {
    if (iosConfig.connectionType === 'ssh') {
      if (!iosConfig.jailbroken) {
        return res.status(400).json({ error: 'SSH not connected' });
      }

      const key = cacheKey('app', bundleId);
      const appDetails = await cachedSSH(key, CACHE_TTL.APP_DETAILS, async () => {
        const plistBuddy = iosConfig.rootless 
          ? '/var/jb/usr/libexec/PlistBuddy' 
          : '/usr/libexec/PlistBuddy';

        
        const findBundleCmd = `
for app in /var/containers/Bundle/Application/*/*.app; do
  plist="$app/Info.plist"
  id=$(${plistBuddy} -c "Print CFBundleIdentifier" "$plist" 2>/dev/null | grep -v "Cannot" | head -1)
  if [ "$id" = "${bundleId}" ]; then
    ver=$(${plistBuddy} -c "Print CFBundleShortVersionString" "$plist" 2>/dev/null | grep -v "Does Not Exist" | grep -v "Cannot" | head -1)
    name=$(basename "$app" .app)
    echo "$id|$name|$ver|$app"
    break
  fi
done
        `.trim();

        const bundleOutput = await sshCommand(findBundleCmd);
        
        if (!bundleOutput || !bundleOutput.includes('|')) {
          return null;
        }

        const [id, name, version, bundlePath] = bundleOutput.trim().split('|');

        const findDataCmd = `
for meta in /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist; do
  bid=$(${plistBuddy} -c "Print MCMMetadataIdentifier" "$meta" 2>/dev/null | grep -v "Cannot" | head -1)
  if [ "$bid" = "${bundleId}" ]; then
    dirname "$meta"
    break
  fi
done
        `.trim();

        let dataPath = '';
        try {
          const dataOutput = await sshCommand(findDataCmd);
          if (dataOutput && dataOutput.startsWith('/var/mobile')) {
            dataPath = dataOutput.trim();
          }
        } catch {}

        return {
          bundleId: id,
          name,
          version: version || '',
          bundlePath,
          dataPath,
          paths: {
            bundle: bundlePath,
            data: dataPath,
            documents: dataPath ? `${dataPath}/Documents` : '',
            library: dataPath ? `${dataPath}/Library` : '',
            caches: dataPath ? `${dataPath}/Library/Caches` : '',
            preferences: dataPath ? `${dataPath}/Library/Preferences` : '',
          }
        };
      }, forceRefresh);

      if (!appDetails) {
        return res.status(404).json({ error: 'App not found' });
      }

      return res.json(appDetails);
    }

    if (!iosConfig.udid) {
      return res.status(400).json({ error: 'No device selected' });
    }

    const output = execCommand(`ideviceinstaller -u ${iosConfig.udid} -l`, 30000);
    
    if (!output) {
      return res.status(404).json({ error: 'App not found' });
    }

    
    const lines = output.split('\n');
    let appLine = '';
    
    for (const line of lines) {
      if (line.startsWith(bundleId + ',')) {
        appLine = line;
        break;
      }
    }

    if (!appLine) {
      return res.status(404).json({ error: 'App not found' });
    }

    
    const match = appLine.match(/^([^,]+),\s*"([^"]*)",\s*"([^"]*)"$/);
    
    if (!match) {
      return res.status(500).json({ error: 'Parse error' });
    }

    return res.json({
      bundleId: match[1].trim(),
      name: match[3].trim(),
      version: match[2].trim(),
      bundlePath: '',
      dataPath: '',
      paths: {}
    });

  } catch (e: any) {
    console.error('Error in /apps/:bundleId:', e);
    res.status(500).json({ error: e.message });
  }
});


router.post('/syslog/start', async (req, res) => {
  const { bundleId } = req.body;

  if (syslogProcess) {
    syslogProcess.kill();
    syslogProcess = null;
  }

  syslogBuffer = [];

  if (iosConfig.connectionType === 'ssh') {
    if (!iosConfig.jailbroken) {
      return res.status(400).json({ error: 'SSH not connected' });
    }
    res.json({ success: true, mode: 'ssh' });
  } else {
    if (!iosConfig.udid) {
      return res.status(400).json({ error: 'No device selected' });
    }

    const args = ['-u', iosConfig.udid];
    if (bundleId) {
      args.push('-m', bundleId);
    }

    syslogProcess = spawn('idevicesyslog', args);

    syslogProcess.stdout?.on('data', (data: Buffer) => {
      const lines = data.toString().split('\n').filter(l => l.trim());
      syslogBuffer.push(...lines);
      if (syslogBuffer.length > 1000) {
        syslogBuffer = syslogBuffer.slice(-1000);
      }
    });

    syslogProcess.on('close', () => {
      syslogProcess = null;
    });

    res.json({ success: true, mode: 'usb' });
  }
});

router.post('/syslog/stop', (req, res) => {
  if (syslogProcess) {
    syslogProcess.kill();
    syslogProcess = null;
  }
  res.json({ success: true });
});

router.get('/syslog/logs', async (req, res) => {
  const since = parseInt(req.query.since as string) || 0;

  if (iosConfig.connectionType === 'ssh' && iosConfig.jailbroken) {
    try {
      const logs = await sshCommand('tail -50 /var/log/syslog 2>/dev/null || dmesg | tail -50');
      const lines = logs.split('\n').filter(l => l.trim());
      const newLines = lines.slice(Math.max(0, since - (lines.length - 50)));
      
      res.json({
        running: true,
        logs: newLines,
        newIndex: lines.length,
      });
    } catch {
      res.json({ running: false, logs: [], newIndex: 0 });
    }
  } else {
    res.json({
      running: syslogProcess !== null,
      logs: syslogBuffer.slice(since),
      newIndex: syslogBuffer.length,
    });
  }
});

router.post('/file/list', async (req, res) => {
  const { path: dirPath } = req.body;
  const forceRefresh = req.query.refresh === 'true';

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const safePath = dirPath || '/';
    const key = cacheKey('files', safePath);
    
    const files = await cachedSSH(key, CACHE_TTL.FILE_LIST, async () => {
      const output = await sshCommand(`ls -la "${safePath}"`);
      const lines = output.split('\n').slice(1);

      return lines.map(line => {
        const parts = line.split(/\s+/);
        if (parts.length >= 9) {
          const perms = parts[0];
          const size = parts[4];
          const name = parts.slice(8).join(' ');
          
          if (name === '.' || name === '..') return null;
          
          return {
            name,
            size,
            permissions: perms,
            isDirectory: perms.startsWith('d'),
            isSymlink: perms.startsWith('l'),
            path: safePath === '/' ? `/${name}` : `${safePath}/${name}`,
          };
        }
        return null;
      }).filter(Boolean);
    }, forceRefresh);

    res.json(files);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/file/read', async (req, res) => {
  const { path: filePath } = req.body;
  const forceRefresh = req.query.refresh === 'true';

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const key = cacheKey('file', filePath);
    
    const fileData = await cachedSSH(key, CACHE_TTL.FILE_CONTENT, async () => {
      const content = await sshCommand(`cat "${filePath}" | base64`);
      return {
        content: Buffer.from(content, 'base64').toString('utf-8'),
        base64: content,
      };
    }, forceRefresh);

    res.json({ success: true, ...fileData });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/file/pull', async (req, res) => {
  const { remotePath } = req.body;

  if (!remotePath) {
    return res.status(400).json({ error: 'Remote path required' });
  }

  if (!iosConfig.jailbroken && iosConfig.connectionType === 'ssh') {
    return res.status(400).json({ error: 'SSH not connected' });
  }

  try {
    let data: Buffer;

    if (iosConfig.connectionType === 'ssh') {
      const content = await sshCommand(`cat "${remotePath}" | base64`);
      data = Buffer.from(content, 'base64');
    } else {
      const localPath = `/tmp/ios_pull_${Date.now()}_${path.basename(remotePath)}`;
      execCommand(`idevicefs -u ${iosConfig.udid} pull "${remotePath}" "${localPath}"`);
      
      if (fs.existsSync(localPath)) {
        data = fs.readFileSync(localPath);
        fs.unlinkSync(localPath);
      } else {
        return res.status(500).json({ error: 'Pull failed' });
      }
    }

    res.json({
      success: true,
      filename: path.basename(remotePath),
      data: data.toString('base64'),
      size: data.length,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/file/push', async (req, res) => {
  const { content, remotePath, base64 } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const data = base64 || Buffer.from(content).toString('base64');
    await sshCommand(`echo "${data}" | base64 -d > "${remotePath}"`);
    
    
    const parentPath = path.dirname(remotePath);
    await invalidateCache(cacheKey('files', parentPath));
    
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/file/delete', async (req, res) => {
  const { path: filePath } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    await sshRoot(`rm -rf "${filePath}"`);
    
    
    const parentPath = path.dirname(filePath);
    await invalidateCache(cacheKey('files', parentPath));
    await invalidateCache(cacheKey('file', filePath));
    
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/security/keychain', async (req, res) => {
  const { bundleId } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    let cmd = 'keychain-dumper 2>/dev/null';
    if (bundleId) {
      cmd += ` | grep -A 20 "${bundleId}"`;
    }
    const output = await sshRoot(cmd);
    res.json({ success: true, output: output || 'No keychain data found or keychain-dumper not installed' });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/security/plist', async (req, res) => {
  const { path: plistPath } = req.body;
  const forceRefresh = req.query.refresh === 'true';

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const key = cacheKey('plist', plistPath);
    
    const output = await cachedSSH(key, CACHE_TTL.FILE_CONTENT, async () => {
      const plutil = iosConfig.rootless ? '/var/jb/usr/bin/plutil' : 'plutil';
      return await sshCommand(`${plutil} -show "${plistPath}"`);
    }, forceRefresh);

    res.json({ success: true, output });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/security/strings', async (req, res) => {
  const { binaryPath } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const output = await sshCommand(`strings "${binaryPath}" 2>/dev/null | head -500`);
    const lines = output.split('\n');
    
    
    const sensitivePatterns = [
      /password/i, /secret/i, /api[_-]?key/i, /token/i, /auth/i,
      /private/i, /credential/i, /https?:\/\//i, /[A-Za-z0-9+/]{40,}/
    ];
    
    const sensitiveStrings = lines.filter(line => 
      sensitivePatterns.some(p => p.test(line))
    );

    res.json({
      success: true,
      totalStrings: lines.length,
      sensitiveStrings,
      sample: lines.slice(0, 100),
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/security/binary-info', async (req, res) => {
  const { binaryPath } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const jtool2 = iosConfig.rootless ? '/var/jb/usr/bin/jtool2' : 'jtool2';
    
    const [header, libs] = await Promise.all([
      sshCommand(`${jtool2} -hv "${binaryPath}" 2>/dev/null | head -20`),
      sshCommand(`${jtool2} -L "${binaryPath}" 2>/dev/null | head -30`),
    ]);

    const pie = header.includes('PIE');
    const encrypted = header.includes('ENCRYPTED') || header.includes('cryptid 1');
    const stackCanary = libs.includes('libSystem') || libs.includes('stack_chk');
    const arc = libs.includes('libobjc');

    const frameworks = libs.split('\n')
      .filter(l => l.includes('/'))
      .map(l => l.trim().split(' ')[0])
      .filter(Boolean);

    res.json({
      success: true,
      file: path.basename(binaryPath),
      pie,
      encrypted,
      stackCanary,
      arc,
      frameworks,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/security/sqlite', async (req, res) => {
  const { dbPath, query } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const sqlQuery = query || '.tables';
    const output = await sshCommand(`sqlite3 "${dbPath}" "${sqlQuery}" 2>/dev/null`);
    res.json({ success: true, output, query: sqlQuery, path: dbPath });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/security/nsuserdefaults', async (req, res) => {
  const { bundleId } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const findCmd = `find /var/mobile/Containers/Data/Application -name "${bundleId}.plist" -path "*/Library/Preferences/*" 2>/dev/null | head -1`;
    const prefsPath = await sshCommand(findCmd);

    if (!prefsPath) {
      return res.json({ success: true, output: 'No preferences file found' });
    }

    const plutil = iosConfig.rootless ? '/var/jb/usr/bin/plutil' : 'plutil';
    const output = await sshCommand(`${plutil} -show "${prefsPath.trim()}" 2>/dev/null`);
    
    res.json({ success: true, output, path: prefsPath.trim() });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/security/cookies', async (req, res) => {
  const { bundleId } = req.body;

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    let findCmd: string;
    if (bundleId) {
      findCmd = `find /var/mobile/Containers/Data/Application -name "Cookies.binarycookies" 2>/dev/null | xargs -I{} sh -c 'grep -l "${bundleId}" "$(dirname {})"/../.com.apple.mobile_container_manager.metadata.plist 2>/dev/null && echo {}'`;
    } else {
      findCmd = `find /var/mobile -name "Cookies.binarycookies" 2>/dev/null`;
    }

    const cookiesPath = await sshCommand(findCmd);
    
    if (!cookiesPath) {
      return res.json({ success: true, cookies: [], message: 'No cookies found' });
    }

    const paths = cookiesPath.split('\n').filter(Boolean);
    const cookies: string[] = [];

    for (const p of paths.slice(0, 5)) {
      try {
        const content = await sshCommand(`strings "${p}" 2>/dev/null | head -50`);
        cookies.push(`=== ${p} ===\n${content}`);
      } catch {}
    }

    res.json({ success: true, cookies });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/binaries', async (req, res) => {
  const forceRefresh = req.query.refresh === 'true';

  if (!iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const key = cacheKey('binaries');
    
    const binaries = await cachedSSH(key, CACHE_TTL.BINARIES, async () => {
      const prefix = iosConfig.rootless ? '/var/jb' : '';
      const bins = await sshCommand(`ls ${prefix}/usr/bin ${prefix}/usr/local/bin 2>/dev/null | sort -u`);
      return bins.split('\n').filter(Boolean);
    }, forceRefresh);

    res.json({ success: true, binaries });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/cache/invalidate', async (req, res) => {
  const { pattern } = req.body;
  
  try {
    if (pattern) {
      await invalidateCache(cacheKey(pattern, '*'));
    } else {
      await invalidateDeviceCache();
    }
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/cache/stats', async (req, res) => {
  try {
    const host = iosConfig.sshHost || iosConfig.udid || 'unknown';
    const keys = await redis.keys(`ios:${host}:*`);
    
    const stats: Record<string, number> = {};
    for (const key of keys) {
      const type = key.split(':')[2] || 'unknown';
      stats[type] = (stats[type] || 0) + 1;
    }

    res.json({
      success: true,
      totalKeys: keys.length,
      byType: stats,
      host,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

async function sftpDownload(remotePath: string, localPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const conn = new Client();

    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) {
          conn.end();
          return reject(err);
        }

        sftp.fastGet(remotePath, localPath, (err) => {
          conn.end();
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    });

    conn.on('error', (err) => reject(err));

    conn.connect({
      host: iosConfig.sshHost,
      port: iosConfig.sshPort,
      username: iosConfig.sshUser,
      password: iosConfig.sshPassword,
      readyTimeout: 30000,
    });
  });
}

router.post('/extract-ipa', async (req, res) => {
  const { bundleId, bundlePath } = req.body;

  if (!bundleId || !bundlePath) {
    return res.status(400).json({ error: 'bundleId and bundlePath required' });
  }

  if (iosConfig.connectionType !== 'ssh' || !iosConfig.jailbroken) {
    return res.status(400).json({ error: 'Requires SSH connection' });
  }

  try {
    const timestamp = Date.now();
    const appName = bundlePath.split('/').pop()?.replace('.app', '') || bundleId;
    const remoteTemp = '/var/tmp';
    const ipaName = `${appName}_${timestamp}.ipa`;
    const remoteIpa = `${remoteTemp}/${ipaName}`;

    
    const buildCmd = `
	cd ${remoteTemp}
	rm -rf Payload
	mkdir -p Payload
	cp -R "${bundlePath}" Payload/
	zip -qr "${ipaName}" Payload
	rm -rf Payload
	    `.trim();

    console.log('[IPA] Building on device...');
    await sshCommand(buildCmd);

    
    const checkFile = await sshCommand(`test -f "${remoteIpa}" && echo "OK" || echo "FAIL"`);
    if (!checkFile.includes('OK')) {
      return res.status(500).json({ error: 'Failed to create IPA on device' });
    }

   
    const localDir = '/tmp/ios_ipas';
    if (!fs.existsSync(localDir)) {
      fs.mkdirSync(localDir, { recursive: true });
    }
    const localPath = `${localDir}/${ipaName}`;

    
    console.log('[IPA] Downloading via SFTP...');
    await sftpDownload(remoteIpa, localPath);
   
    await sshCommand(`rm -f "${remoteIpa}"`);
    const stats = fs.statSync(localPath);
    console.log('[IPA] Done:', ipaName, stats.size, 'bytes');

    res.json({
      success: true,
      bundleId,
      appName,
      filename: ipaName,
      size: stats.size,
      sizeMB: (stats.size / 1024 / 1024).toFixed(2),
      downloadUrl: `/api/v1/ios/download-ipa/${ipaName}`
    });

  } catch (e: any) {
    console.error('[IPA] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

router.get('/download-ipa/:filename', (req, res) => {
  const { filename } = req.params;
  const localPath = `/tmp/ios_ipas/${filename}`;

  if (!fs.existsSync(localPath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  res.download(localPath, filename, (err) => {
    if (err) {
      console.error('Download error:', err);
    }
  });
});

router.get('/extracted-ipas', (req, res) => {
  const localDir = '/tmp/ios_ipas';

  if (!fs.existsSync(localDir)) {
    return res.json([]);
  }

  const files = fs.readdirSync(localDir)
    .filter(f => f.endsWith('.ipa'))
    .map(f => {
      const stats = fs.statSync(`${localDir}/${f}`);
      return {
        filename: f,
        size: stats.size,
        sizeMB: (stats.size / 1024 / 1024).toFixed(2),
        created: stats.mtime,
        downloadUrl: `/api/v1/ios/download-ipa/${f}`,
      };
    })
    .sort((a, b) => new Date(b.created).getTime() - new Date(a.created).getTime());

  res.json(files);
});

router.delete('/extracted-ipas/:filename', (req, res) => {
  const { filename } = req.params;
  const localPath = `/tmp/ios_ipas/${filename}`;

  if (!fs.existsSync(localPath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    fs.unlinkSync(localPath);
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/extracted-ipas', (req, res) => {
  const localDir = '/tmp/ios_ipas';

  if (!fs.existsSync(localDir)) {
    return res.json({ success: true, deleted: 0 });
  }

  try {
    const files = fs.readdirSync(localDir).filter(f => f.endsWith('.ipa'));
    files.forEach(f => fs.unlinkSync(`${localDir}/${f}`));
    res.json({ success: true, deleted: files.length });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/status', (req, res) => {
  res.json({
    udid: iosConfig.udid,
    connectionType: iosConfig.connectionType,
    jailbroken: iosConfig.jailbroken,
    rootless: iosConfig.rootless,
    sshConfig: {
      host: iosConfig.sshHost,
      port: iosConfig.sshPort,
      user: iosConfig.sshUser,
      connected: iosConfig.jailbroken && iosConfig.connectionType === 'ssh',
    },
    deviceInfo: iosConfig.deviceInfo,
    syslogRunning: syslogProcess !== null,
  });
});

export default router;
