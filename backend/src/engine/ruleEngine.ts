import fs from 'fs';
import path from 'path';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface SecurityFlag {
  flag: string;
  value: string | boolean;
  severity: Severity;
  description: string;
  recommendation: string;
  location: string;
  rawXml?: string;
}

export interface RuleContext {
  platform: 'ANDROID' | 'IOS';
  manifest?: any;
  application?: any;
  plist?: any;
  raw: string;
}

export interface Rule {
  id: string;
  platform: 'ANDROID' | 'IOS';
  file: string;
  severity: Severity;
  flag: string;
  description: string;
  recommendation: string;
  location: string;

  when: {
    type: 'attribute' | 'plist_key';
    path?: string;
    name?: string;
    key?: string;
    operator: 'equals' | 'not_equals' | 'exists' | 'not_exists';
    value?: any;
  };

  evidence?: {
    search?: string;
  };
}

export class RuleEngine {
  constructor(private rules: Rule[]) {}

  evaluate(context: RuleContext): SecurityFlag[] {
    const flags: SecurityFlag[] = [];

    for (const rule of this.rules) {
      if (rule.platform !== context.platform) continue;

      if (this.evaluateCondition(rule.when, context)) {
        flags.push({
          flag: rule.flag,
          value: rule.when.value ?? true,
          severity: rule.severity,
          description: rule.description,
          recommendation: rule.recommendation,
          location: rule.location,
          rawXml: rule.evidence?.search
            ? this.extractSnippet(context.raw, rule.evidence.search)
            : undefined,
        });
      }
    }

    return flags;
  }

  private evaluateCondition(cond: Rule['when'], ctx: RuleContext): boolean {
    if (cond.type === 'attribute') {
      const node =
        cond.path === 'application'
          ? ctx.application
          : ctx.manifest?.[cond.path || ''];

      const value = this.getAttributeValue(node, cond.name!);

      return this.compare(value, cond.operator, cond.value);
    }

    if (cond.type === 'plist_key') {
      const value = this.getNestedKey(ctx.plist, cond.key!);
      return this.compare(value, cond.operator, cond.value);
    }

    return false;
  }

  private compare(actual: any, operator: string, expected: any): boolean {
    switch (operator) {
      case 'equals':
        return actual === expected;
      case 'not_equals':
        return actual !== expected;
      case 'exists':
        return actual !== undefined;
      case 'not_exists':
        return actual === undefined;
      default:
        return false;
    }
  }

  private getAttributeValue(node: any, attr: string): any {
    if (!node) return undefined;

    const keys = [
      `@_${attr}`,
      `@_android:${attr}`,
      `@_android_${attr}`,
      attr,
    ];

    for (const k of keys) {
      if (node[k] !== undefined) {
        return node[k] === 'true' ? true : node[k] === 'false' ? false : node[k];
      }
    }

    return undefined;
  }

  private getNestedKey(obj: any, path: string): any {
    return path.split('.').reduce((acc, key) => acc?.[key], obj);
  }

  private extractSnippet(raw: string, search: string): string {
    const lines = raw.split('\n');
    const idx = lines.findIndex(l => l.includes(search));
    if (idx === -1) return '';
    return lines.slice(Math.max(0, idx - 3), idx + 4).join('\n').trim();
  }
}
