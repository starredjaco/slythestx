import fs from 'fs';
import path from 'path';
import { XMLParser } from 'fast-xml-parser';
import { logger } from '../utils/logger';

const plist = require('plist');

export interface AppInfo {
  packageName: string;
  version: string;
  appName: string;
  filename: string;
}

export class AppInfoParser {
  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS',
    private originalFilePath: string
  ) {}

  async parse(): Promise<AppInfo> {
    if (this.platform === 'ANDROID') {
      return this.parseAndroid();
    } else {
      return this.parseIOS();
    }
  }

  private async parseAndroid(): Promise<AppInfo> {
    const manifestPath = path.join(this.extractPath, 'AndroidManifest.xml');
    const fileName = path.basename(this.originalFilePath);

    if (!fs.existsSync(manifestPath)) {
      logger.warn('AndroidManifest.xml not found');
      return {
        packageName: 'N/A',
        version: 'N/A',
        appName: 'N/A',
        filename: fileName,
      };
    }

    try {
      const content = fs.readFileSync(manifestPath, 'utf-8');
      const parser = new XMLParser({
        ignoreAttributes: false,
        attributeNamePrefix: '@_',
      });
      const manifest = parser.parse(content);
      const manifestNode = manifest.manifest || {};
      const appNode = manifestNode.application || {};

      
      const packageName = manifestNode['@_package'] || 'N/A';
      const version = manifestNode['@_android:versionName'] || manifestNode['@_android:versionCode'] || 'N/A';

      
      let appName = 'N/A';
      const labelAttr = appNode['@_android:label'];
      if (labelAttr) {
        if (labelAttr.startsWith('@string/')) {
          
          const stringName = labelAttr.replace('@string/', '');
          const stringsPath = path.join(this.extractPath, 'res', 'values', 'strings.xml');
          if (fs.existsSync(stringsPath)) {
            const stringsContent = fs.readFileSync(stringsPath, 'utf-8');
            const stringsXml = parser.parse(stringsContent);
            if (stringsXml.resources && stringsXml.resources.string) {
              const strArray = Array.isArray(stringsXml.resources.string)
                ? stringsXml.resources.string
                : [stringsXml.resources.string];
              const match = strArray.find((s: any) => s['@_name'] === stringName);
              if (match && typeof match['#text'] === 'string') {
                appName = match['#text'];
              }
            }
          }
        } else {
          appName = labelAttr;
        }
      }

      return {
        packageName,
        version,
        appName,
        filename: fileName,
      };
    } catch (error) {
      logger.error('Error parsing AndroidManifest.xml:', error);
      return {
        packageName: 'N/A',
        version: 'N/A',
        appName: 'N/A',
        filename: path.basename(this.originalFilePath),
      };
    }
  }

  private async parseIOS(): Promise<AppInfo> {
    const payloadDir = path.join(this.extractPath, 'Payload');
    const fileName = path.basename(this.originalFilePath);

    if (!fs.existsSync(payloadDir)) {
      logger.warn('Payload directory not found');
      return {
        packageName: 'N/A',
        version: 'N/A',
        appName: 'N/A',
        filename: fileName,
      };
    }

    const appDirs = fs.readdirSync(payloadDir).filter(f => f.endsWith('.app'));
    if (appDirs.length === 0) {
      logger.warn('.app directory not found');
      return {
        packageName: 'N/A',
        version: 'N/A',
        appName: 'N/A',
        filename: fileName,
      };
    }

    const appDir = path.join(payloadDir, appDirs[0]);
    const infoPlistPath = path.join(appDir, 'Info.plist');

    if (!fs.existsSync(infoPlistPath)) {
      logger.warn('Info.plist not found in .app directory');
      return {
        packageName: 'N/A',
        version: 'N/A',
        appName: 'N/A',
        filename: fileName,
      };
    }

    try {
      const plistContent = fs.readFileSync(infoPlistPath, 'utf-8');
      const plistData = plist.parse(plistContent);

      return {
        packageName: plistData.CFBundleIdentifier || 'N/A',
        version: plistData.CFBundleShortVersionString || plistData.CFBundleVersion || 'N/A',
        appName: plistData.CFBundleDisplayName || plistData.CFBundleName || 'N/A',
        filename: fileName,
      };
    } catch (error) {
      logger.error('Error parsing Info.plist:', error);
      return {
        packageName: 'N/A',
        version: 'N/A',
        appName: 'N/A',
        filename: fileName,
      };
    }
  }
}
