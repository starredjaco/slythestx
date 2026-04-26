import { query } from './connection';

export interface User {
  id: number;
  email: string;
  password: string;
  full_name?: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface Application {
  id: number;
  name: string;
  package_name?: string;
  version?: string;
  platform: 'ANDROID' | 'IOS';
  technology: string;
  file_hash: string;
  file_size?: number;
  file_path: string;
  original_filename: string;
  status: 'UPLOADED' | 'EXTRACTING' | 'ANALYZING' | 'COMPLETED' | 'FAILED';
  analysis_progress: number;
  security_score?: number;
  uploaded_by_id: number;
  created_at: Date;
  updated_at: Date;
  analyzed_at?: Date;
}

export interface AnalysisResult {
  id: number;
  application_id: number;
  manifest_data?: any;
  permissions?: any;
  components?: any;
  secrets_found?: any;
  certificate_info?: any;
  network_security?: any;
  storage_analysis?: any;
  code_analysis?: any;
  total_files: number;
  total_strings: number;
  total_permissions: number;
  dangerous_permissions_count: number;
  evidences?: any;
  occurrences?: number;
  created_at: Date;
}

export interface Vulnerability {
  id: number;
  application_id: number;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  owasp_category?: string;
  cve_id?: string;
  cvss_score?: string;
  recommendation?: string;
  reference_links?: any;
  evidences?: string;
  occurrences?: number;
  created_at: Date;
}

// ------------------- User -------------------
export const userModel = {
  findByEmail: async (email: string): Promise<User | null> => {
    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
    return result.rows[0] || null;
  },

  create: async (data: { email: string; password: string; full_name?: string }): Promise<User> => {
    const result = await query(
      'INSERT INTO users (email, password, full_name) VALUES ($1, $2, $3) RETURNING *',
      [data.email, data.password, data.full_name]
    );
    return result.rows[0];
  },
};

// ------------------- Application -------------------
export const applicationModel = {
  findByHash: async (hash: string): Promise<Application | null> => {
    const result = await query('SELECT * FROM applications WHERE file_hash = $1', [hash]);
    return result.rows[0] || null;
  },

  findAll: async (params: { page?: number; pageSize?: number; platform?: string; status?: string }) => {
    const page = params.page || 1;
    const pageSize = params.pageSize || 20;
    const offset = (page - 1) * pageSize;

    let whereConditions: string[] = [];
    let queryParams: any[] = [];
    let paramIndex = 1;

    if (params.platform) {
      whereConditions.push(`platform = $${paramIndex}`);
      queryParams.push(params.platform);
      paramIndex++;
    }

    if (params.status) {
      whereConditions.push(`status = $${paramIndex}`);
      queryParams.push(params.status);
      paramIndex++;
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const [dataResult, countResult] = await Promise.all([
      query(
        `SELECT * FROM applications ${whereClause} ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
        [...queryParams, pageSize, offset]
      ),
      query(`SELECT COUNT(*) FROM applications ${whereClause}`, queryParams),
    ]);

    return {
      applications: dataResult.rows,
      total: parseInt(countResult.rows[0].count),
    };
  },

  findById: async (id: number): Promise<Application | null> => {
    const result = await query('SELECT * FROM applications WHERE id = $1', [id]);
    return result.rows[0] || null;
  },

  create: async (data: {
    name: string;
    platform: string;
    file_hash: string;
    file_size: number;
    file_path: string;
    original_filename: string;
    uploaded_by_id: number;
  }): Promise<Application> => {
    const result = await query(
      `INSERT INTO applications (name, platform, file_hash, file_size, file_path, original_filename, uploaded_by_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [data.name, data.platform, data.file_hash, data.file_size, data.file_path, data.original_filename, data.uploaded_by_id]
    );
    return result.rows[0];
  },

  update: async (id: number, data: Partial<Application>): Promise<Application> => {
    const fields = Object.keys(data);
    const values = Object.values(data);
    const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');

    const result = await query(
      `UPDATE applications SET ${setClause}, updated_at = CURRENT_TIMESTAMP WHERE id = $${fields.length + 1} RETURNING *`,
      [...values, id]
    );
    return result.rows[0];
  },

  delete: async (id: number): Promise<void> => {
    await query('DELETE FROM applications WHERE id = $1', [id]);
  },

  getStatistics: async (): Promise<any> => {
    const [total, android, ios, completed, scores] = await Promise.all([
      query('SELECT COUNT(*) FROM applications'),
      query('SELECT COUNT(*) FROM applications WHERE platform = $1', ['ANDROID']),
      query('SELECT COUNT(*) FROM applications WHERE platform = $1', ['IOS']),
      query('SELECT COUNT(*) FROM applications WHERE status = $1', ['COMPLETED']),
      query('SELECT security_score FROM applications WHERE security_score IS NOT NULL AND status = $1', ['COMPLETED']),
    ]);

    const avgScore =
      scores.rows.length > 0 ? scores.rows.reduce((sum, row) => sum + row.security_score, 0) / scores.rows.length : 0;

    return {
      total_applications: parseInt(total.rows[0].count),
      android_applications: parseInt(android.rows[0].count),
      ios_applications: parseInt(ios.rows[0].count),
      completed_applications: parseInt(completed.rows[0].count),
      average_security_score: Math.round(avgScore),
    };
  },
};

// ------------------- AnalysisResult -------------------
export const analysisResultModel = {
  findByApplicationId: async (applicationId: number): Promise<AnalysisResult | null> => {
    const result = await query('SELECT * FROM analysis_results WHERE application_id = $1', [applicationId]);
    return result.rows[0] || null;
  },

  create: async (data: {
    application_id: number;
    manifest_data?: any;
    permissions?: any;
    components?: any;
    secrets_found?: any;
    total_files?: number;
    total_strings?: number;
    total_permissions?: number;
    dangerous_permissions_count?: number;
  }): Promise<AnalysisResult> => {
    const result = await query(
      `INSERT INTO analysis_results (
        application_id, manifest_data, permissions, components, secrets_found, 
        total_files, total_strings, total_permissions, dangerous_permissions_count
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [
        data.application_id,
        data.manifest_data ? JSON.stringify(data.manifest_data) : null,
        data.permissions ? JSON.stringify(data.permissions) : null,
        data.components ? JSON.stringify(data.components) : null,
        data.secrets_found ? JSON.stringify(data.secrets_found) : null,
        data.total_files || 0,
        data.total_strings || 0,
        data.total_permissions || 0,
        data.dangerous_permissions_count || 0,
      ]
    );
    return result.rows[0];
  },

  deleteByApplicationId: async (applicationId: number): Promise<void> => {
    await query('DELETE FROM analysis_results WHERE application_id = $1', [applicationId]);
  },
};

// ------------------- Vulnerability -------------------
export const vulnerabilityModel = {
  findByApplicationId: async (applicationId: number): Promise<Vulnerability[]> => {
    const result = await query('SELECT * FROM vulnerabilities WHERE application_id = $1 ORDER BY severity DESC', [
      applicationId,
    ]);
    return result.rows;
  },

  create: async (data: {
    application_id: number;
    title: string;
    description: string;
    severity: string;
    category: string;
    file_path?: string;
    line_number?: number;
    code_snippet?: string;
    owasp_category?: string;
    recommendation?: string;
    evidences?: string;
    occurrences?: number;
  }): Promise<Vulnerability> => {
    const result = await query(
      `INSERT INTO vulnerabilities (
        application_id, title, description, severity, category,
        file_path, line_number, code_snippet, owasp_category, recommendation,
        evidences, occurrences
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [
        data.application_id,
        data.title,
        data.description,
        data.severity,
        data.category,
        data.file_path,
        data.line_number,
        data.code_snippet,
        data.owasp_category,
        data.recommendation,
        data.evidences || null,
        data.occurrences ?? 1,
      ]
    );
    return result.rows[0];
  },

  getSummary: async (applicationId: number): Promise<any> => {
    const result = await query(
      `SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
        COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
        COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
        COUNT(*) FILTER (WHERE severity = 'LOW') as low,
        COUNT(*) FILTER (WHERE severity = 'INFO') as info
      FROM vulnerabilities WHERE application_id = $1`,
      [applicationId]
    );

    return {
      total_vulnerabilities: parseInt(result.rows[0].total),
      critical_vulnerabilities: parseInt(result.rows[0].critical),
      high_vulnerabilities: parseInt(result.rows[0].high),
      medium_vulnerabilities: parseInt(result.rows[0].medium),
      low_vulnerabilities: parseInt(result.rows[0].low),
      info_vulnerabilities: parseInt(result.rows[0].info),
    };
  },


  deleteByApplicationId: async (applicationId: number): Promise<void> => {
    await query('DELETE FROM vulnerabilities WHERE application_id = $1', [applicationId]);
  },
};
