import { Pool } from 'pg';
import { logger } from '../utils/logger';

export async function initDatabase() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@db:5432/mobile_security',
  });


  const maxRetries = 30;
  for (let i = 0; i < maxRetries; i++) {
    try {
      await pool.query('SELECT 1');
      logger.info('✅ PostgreSQL conectado');
      break;
    } catch (error) {
      if (i === maxRetries - 1) {
        logger.error('Error conecting to PostgreSQL');
        process.exit(1);
      }
      logger.info(`⏳ Esperando PostgreSQL... (${i + 1}/${maxRetries})`);
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  try {
    logger.info('📋 Creando tabla applications...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS applications (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          package_name VARCHAR(255),
          version VARCHAR(100),
          platform VARCHAR(50) NOT NULL,
          technology VARCHAR(50) DEFAULT 'UNKNOWN',
          file_hash VARCHAR(64) UNIQUE NOT NULL,
          file_size BIGINT,
          file_path TEXT NOT NULL,
          original_filename VARCHAR(255) NOT NULL,
          status VARCHAR(50) DEFAULT 'UPLOADED',
          analysis_progress INTEGER DEFAULT 0,
          security_score INTEGER,
          uploaded_by_id INTEGER DEFAULT 1,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          analyzed_at TIMESTAMP
      )
    `);

    logger.info('📋 Creando tabla analysis_results...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS analysis_results (
          id SERIAL PRIMARY KEY,
          application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
          manifest_data JSONB,
          permissions JSONB,
          components JSONB,
          secrets_found JSONB,
          certificate_info JSONB,
          network_security JSONB,
          storage_analysis JSONB,
          code_analysis JSONB,
          total_files INTEGER DEFAULT 0,
          total_strings INTEGER DEFAULT 0,
          total_permissions INTEGER DEFAULT 0,
          dangerous_permissions_count INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    logger.info('📋 Creando tabla vulnerabilities...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS vulnerabilities (
          id SERIAL PRIMARY KEY,
          application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
          title VARCHAR(255) NOT NULL,
          description TEXT NOT NULL,
          severity VARCHAR(50) NOT NULL,
          category VARCHAR(100) NOT NULL,
          file_path TEXT,
          line_number INTEGER,
          code_snippet TEXT,
          owasp_category VARCHAR(100),
          cve_id VARCHAR(50),
          cvss_score VARCHAR(20),
          recommendation TEXT,
          reference_links JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          evidences TEXT,
          occurrences INTEGER DEFAULT 1
      )
    `);

    logger.info('📊 Creando índices...');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_applications_file_hash ON applications(file_hash)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_app_id ON vulnerabilities(application_id)');

    logger.info('✅ Tablas e índices creados exitosamente');
  } catch (error) {
    logger.error('❌ Error inicializando tablas:', error);
    throw error;
  }

  await pool.end();
}
