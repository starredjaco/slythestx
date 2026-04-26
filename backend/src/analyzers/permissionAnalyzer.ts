import fs from 'fs';
import path from 'path';
import { XMLParser } from 'fast-xml-parser';
import { logger } from '../utils/logger';
var plist = require('plist');


const DANGEROUS_ANDROID_PERMISSIONS: Record<string, string> = {
  'android.permission.READ_CONTACTS': 'Access contacts',
  'android.permission.WRITE_CONTACTS': 'Modify contacts',
  'android.permission.READ_CALENDAR': 'Read calendar',
  'android.permission.WRITE_CALENDAR': 'Write calendar',
  'android.permission.CAMERA': 'Access camera',
  'android.permission.RECORD_AUDIO': 'Record audio',
  'android.permission.ACCESS_FINE_LOCATION': 'Precise location',
  'android.permission.ACCESS_COARSE_LOCATION': 'Approximate location',
  'android.permission.READ_PHONE_STATE': 'Read phone state',
  'android.permission.CALL_PHONE': 'Make phone calls',
  'android.permission.READ_CALL_LOG': 'Read call log',
  'android.permission.WRITE_CALL_LOG': 'Write call log',
  'android.permission.SEND_SMS': 'Send SMS',
  'android.permission.RECEIVE_SMS': 'Receive SMS',
  'android.permission.READ_SMS': 'Read SMS',
  'android.permission.READ_EXTERNAL_STORAGE': 'Read storage',
  'android.permission.WRITE_EXTERNAL_STORAGE': 'Write storage',
  'android.permission.BODY_SENSORS': 'Access body sensors',
  'android.permission.ACCESS_BACKGROUND_LOCATION': 'Background location',
};

export interface PermissionAnalysisResult {
  total_permissions: number;
  dangerous_permissions: Array<{
    name: string;
    description: string;
    severity: string;
  }>;
  dangerous_count: number;
  normal_permissions: Array<{
    name: string;
    severity: string;
  }>;
  all_permissions: string[];
}

export class PermissionAnalyzer {
  constructor(
    private extractPath: string,
    private platform: 'ANDROID' | 'IOS'
  ) {}

  async analyze(): Promise<PermissionAnalysisResult> {
    if (this.platform === 'ANDROID') {
      return this.analyzeAndroid();
    } else {
      return this.analyzeIOS();
    }
  }

  private async analyzeAndroid(): Promise<PermissionAnalysisResult> {
    const manifestPath = path.join(this.extractPath, 'AndroidManifest.xml');

    if (!fs.existsSync(manifestPath)) {
      logger.warn('AndroidManifest.xml not found');
      return this.emptyResult();
    }

    try {
      const manifestContent = fs.readFileSync(manifestPath, 'utf-8');
      const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
      const manifest = parser.parse(manifestContent);

      const permissions: string[] = [];
      const usesPermissions = manifest.manifest?.['uses-permission'];
      const permArray = Array.isArray(usesPermissions) ? usesPermissions : [usesPermissions];

      for (const perm of permArray) {
        const permName = perm?.['@_android:name'] || perm?.['@_name'];
        if (permName) permissions.push(permName);
      }

      const dangerous: Array<{ name: string; description: string; severity: string }> = [];
      const normal: Array<{ name: string; severity: string }> = [];

      for (const perm of permissions) {
        if (perm in DANGEROUS_ANDROID_PERMISSIONS) {
          dangerous.push({ name: perm, description: DANGEROUS_ANDROID_PERMISSIONS[perm], severity: 'dangerous' });
        } else if (perm.startsWith('android.permission')) {
          normal.push({ name: perm, severity: 'normal' });
        } else {
          normal.push({ name: perm, severity: 'unknown' });
        }
      }

      return {
        total_permissions: permissions.length,
        dangerous_permissions: dangerous,
        dangerous_count: dangerous.length,
        normal_permissions: normal,
        all_permissions: permissions,
      };
    } catch (error) {
      logger.error('Error analyzing Android permissions:', error);
      return this.emptyResult();
    }
  }

  private async analyzeIOS(): Promise<PermissionAnalysisResult> {
    const payloadDir = path.join(this.extractPath, 'Payload');
    if (!fs.existsSync(payloadDir)) {
      logger.warn('Payload directory not found');
      return this.emptyResult();
    }

    const appDirs = fs.readdirSync(payloadDir).filter(f => f.endsWith('.app'));
    if (appDirs.length === 0) {
      logger.warn('.app directory not found');
      return this.emptyResult();
    }

    const appDir = path.join(payloadDir, appDirs[0]);
    const infoPlistPath = path.join(appDir, 'Info.plist');

    if (!fs.existsSync(infoPlistPath)) {
      logger.warn('Info.plist not found in .app directory');
      return this.emptyResult();
    }

    try {
      const plistContent = fs.readFileSync(infoPlistPath, 'utf-8');
      const plistData = plist.parse(plistContent) as Record<string, any>;

      const privacyKeys: Record<string, string> = {
        'NSCameraUsageDescription': 'Camera',
        'NSPhotoLibraryUsageDescription': 'Photo Library',
        'NSLocationWhenInUseUsageDescription': 'Location (When in Use)',
        'NSLocationAlwaysUsageDescription': 'Location (Always)',
        'NSMicrophoneUsageDescription': 'Microphone',
        'NSContactsUsageDescription': 'Contacts',
        'NSCalendarsUsageDescription': 'Calendars',
        'NSRemindersUsageDescription': 'Reminders',
        'NSMotionUsageDescription': 'Motion & Fitness',
        'NSHealthShareUsageDescription': 'Health Data (Read)',
        'NSHealthUpdateUsageDescription': 'Health Data (Write)',
        'NSBluetoothPeripheralUsageDescription': 'Bluetooth',
        'NSFaceIDUsageDescription': 'Face ID',
      };

      const dangerous: Array<{ name: string; description: string; severity: string }> = [];

      for (const [key, type] of Object.entries(privacyKeys)) {
        if (key in plistData) {
          dangerous.push({
            name: key,
            description: plistData[key],
            severity: 'privacy_sensitive',
          });
        }
      }

      return {
        total_permissions: dangerous.length,
        dangerous_permissions: dangerous,
        dangerous_count: dangerous.length,
        normal_permissions: [],
        all_permissions: Object.keys(plistData),
      };
    } catch (error) {
      logger.error('Error analyzing iOS permissions:', error);
      return this.emptyResult();
    }
  }

  private emptyResult(): PermissionAnalysisResult {
    return {
      total_permissions: 0,
      dangerous_permissions: [],
      dangerous_count: 0,
      normal_permissions: [],
      all_permissions: [],
    };
  }
}
