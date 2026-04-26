import fs from 'fs';
import path from 'path';
import { XMLParser } from 'fast-xml-parser';
import { logger } from '../utils/logger';
import { RuleEngine, Rule, SecurityFlag as RuleSecurityFlag } from '../engine/ruleEngine';

const plist = require('plist');

export interface DeepLink {
  scheme: string;
  host?: string;
  pathPrefix?: string;
  autoVerify?: boolean;
  type: 'intent-filter' | 'app-link' | 'universal-link' | 'custom-scheme';
  rawXml?: string;
}

export interface SecurityFlag {
  flag: string;
  value: string | boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
  location: string;
  rawXml?: string;
}

export interface ManifestAnalysisResult {
  deeplinks: DeepLink[];
  securityFlags: SecurityFlag[];
  exportedComponents: Array<{
    type: 'activity' | 'service' | 'receiver' | 'provider';
    name: string;
    exported: boolean;
    hasIntentFilter: boolean;
    permissions?: string[];
    rawXml?: string;
  }>;
  backupEnabled: boolean;
  debuggable: boolean;
  allowCleartext: boolean;
  minSdkVersion?: number;
  targetSdkVersion?: number;
}

export class ManifestAnalyzer {
  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS'
  ) {}

  async analyze(): Promise<ManifestAnalysisResult> {
    return this.platform === 'ANDROID'
      ? this.analyzeAndroid()
      : this.analyzeIOS();
  }

  private async analyzeAndroid(): Promise<ManifestAnalysisResult> {
    const manifestPath = path.join(this.extractPath, 'AndroidManifest.xml');

    if (!fs.existsSync(manifestPath)) {
      logger.warn('AndroidManifest.xml not found');
      return this.emptyResult();
    }

    const rawXml = fs.readFileSync(manifestPath, 'utf-8');
    if (!rawXml.trim()) return this.emptyResult();

    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      allowBooleanAttributes: true,
      removeNSPrefix: true,
    });

    const parsed = parser.parse(rawXml);
    const manifest = parsed?.manifest;
    if (!manifest) return this.emptyResult();

    const application = manifest.application || {};


    const deeplinks = this.extractDeepLinksAndroid(manifest, rawXml);

  
    const exportedComponents = this.extractExportedComponents(application, rawXml);

  
    const rules = this.loadRules('android/manifest.json');
    const engine = new RuleEngine(rules);

    const securityFlags = engine.evaluate({
      platform: 'ANDROID',
      manifest,
      application,
      raw: rawXml,
    }) as SecurityFlag[];

   
    const backupEnabled = this.getAttr(application, 'allowBackup', false);
    const debuggable = this.getAttr(application, 'debuggable', false);
    const allowCleartext = this.getAttr(application, 'usesCleartextTraffic', false);

    const minSdkVersion = this.getAttr(manifest['uses-sdk'], 'minSdkVersion');
    const targetSdkVersion = this.getAttr(manifest['uses-sdk'], 'targetSdkVersion');

    logger.info(`✅ Android manifest analyzed: ${securityFlags.length} flags`);

    return {
      deeplinks,
      securityFlags,
      exportedComponents,
      backupEnabled,
      debuggable,
      allowCleartext,
      minSdkVersion: minSdkVersion ? Number(minSdkVersion) : undefined,
      targetSdkVersion: targetSdkVersion ? Number(targetSdkVersion) : undefined,
    };
  }

private async analyzeIOS(): Promise<ManifestAnalysisResult> {
    const payload = path.join(this.extractPath, 'Payload');
    if (!fs.existsSync(payload)) return this.emptyResult();

    const appDir = fs.readdirSync(payload).find(f => f.endsWith('.app'));
    if (!appDir) return this.emptyResult();

    const plistPath = path.join(payload, appDir, 'Info.plist');
    if (!fs.existsSync(plistPath)) return this.emptyResult();

    let rawPlist: string;
    let plistData: any;

    try {
        rawPlist = fs.readFileSync(plistPath, 'utf-8');
        plistData = plist.parse(rawPlist);
    } catch (err) {
        logger.warn(`⚠️ Failed to parse Info.plist: ${plistPath}`, err);
        
        return {
            deeplinks: [],
            securityFlags: [],
            exportedComponents: [],
            backupEnabled: false,
            debuggable: false,
            allowCleartext: false,
        };
    }

    const deeplinks = this.extractDeepLinksIOS(plistData, rawPlist);

    const rules = this.loadRules('ios/info.plist.json');
    const engine = new RuleEngine(rules);

    const securityFlags = engine.evaluate({
        platform: 'IOS',
        plist: plistData,
        raw: rawPlist,
    }) as SecurityFlag[];

    logger.info(`✅ iOS Info.plist analyzed: ${securityFlags.length} flags`);

    return {
        deeplinks,
        securityFlags,
        exportedComponents: [],
        backupEnabled: false,
        debuggable: false,
        allowCleartext: false,
    };
}

  private loadRules(relativePath: string): Rule[] {
    const rulesPath = path.join(process.cwd(), 'rules', relativePath);
    return JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
  }

  private getAttr(node: any, name: string, def?: any): any {
    if (!node) return def;
    return (
      node[`@_${name}`] ??
      node[`@_android:${name}`] ??
      node[name] ??
      def
    );
  }

  private toArray(v: any): any[] {
    return Array.isArray(v) ? v : v ? [v] : [];
  }


  private extractDeepLinksAndroid(manifest: any, raw: string): DeepLink[] {
    const result: DeepLink[] = [];
    const activities = this.toArray(manifest.application?.activity);

    for (const act of activities) {
      for (const f of this.toArray(act['intent-filter'])) {
        const actions = this.toArray(f.action);
        const categories = this.toArray(f.category);
        const data = this.toArray(f.data);

        const isView = actions.some(a => this.getAttr(a, 'name') === 'android.intent.action.VIEW');
        if (!isView) continue;

        const browsable = categories.some(c => this.getAttr(c, 'name') === 'android.intent.category.BROWSABLE');
        const autoVerify = this.getAttr(f, 'autoVerify', false);

        for (const d of data) {
          const scheme = this.getAttr(d, 'scheme');
          if (!scheme) continue;

          result.push({
            scheme,
            host: this.getAttr(d, 'host'),
            pathPrefix: this.getAttr(d, 'pathPrefix'),
            autoVerify,
            type: autoVerify ? 'app-link' : browsable ? 'intent-filter' : 'custom-scheme',
          });
        }
      }
    }
    return result;
  }

  private extractExportedComponents(application: any, raw: string): any[] {
    const out: any[] = [];
    const types = ['activity', 'service', 'receiver', 'provider'];

    for (const type of types) {
      for (const c of this.toArray(application[type])) {
        const exported = this.getAttr(c, 'exported');
        const hasIF = !!c['intent-filter'];

        if (exported === true || exported === 'true' || (exported !== false && hasIF)) {
          out.push({
            type,
            name: this.getAttr(c, 'name'),
            exported: true,
            hasIntentFilter: hasIF,
          });
        }
      }
    }
    return out;
  }

  private extractDeepLinksIOS(plistData: any, raw: string): DeepLink[] {
    const result: DeepLink[] = [];

    for (const t of plistData.CFBundleURLTypes || []) {
      for (const s of t.CFBundleURLSchemes || []) {
        result.push({ scheme: s, type: 'custom-scheme' });
      }
    }

    for (const d of plistData['com.apple.developer.associated-domains'] || []) {
      if (d.startsWith('applinks:')) {
        result.push({
          scheme: 'https',
          host: d.replace('applinks:', ''),
          type: 'universal-link',
          autoVerify: true,
        });
      }
    }
    return result;
  }

  private emptyResult(): ManifestAnalysisResult {
    return {
      deeplinks: [],
      securityFlags: [],
      exportedComponents: [],
      backupEnabled: false,
      debuggable: false,
      allowCleartext: false,
    };
  }
}
