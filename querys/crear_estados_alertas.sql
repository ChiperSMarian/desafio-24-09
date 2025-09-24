-- 1) Catálogo de estados
CREATE TABLE IF NOT EXISTS estado_alerta (
  id_status SERIAL PRIMARY KEY,
  codigo    TEXT NOT NULL UNIQUE,                   -- '1 = new' | '2 = processing' | '3 = finished'
  descripcion TEXT
);

-- 2) Semilla básica
INSERT INTO estado_alerta (codigo, descripcion) VALUES
  ('new','Alerta nueva'),
  ('processing','Alerta en proceso'),
  ('finished','Alerta resuelta')
ON CONFLICT (codigo) DO NOTHING;

-- 3) Añadir columna de estado a cada tabla de alertas
ALTER TABLE alertas_ddos            ADD COLUMN IF NOT EXISTS id_status INTEGER REFERENCES estado_alerta(id_status);
ALTER TABLE alertas_dos             ADD COLUMN IF NOT EXISTS id_status INTEGER REFERENCES estado_alerta(id_status);
ALTER TABLE alertas_fuerza_bruta    ADD COLUMN IF NOT EXISTS id_status INTEGER REFERENCES estado_alerta(id_status);
ALTER TABLE alertas_login_sospechoso ADD COLUMN IF NOT EXISTS id_status INTEGER REFERENCES estado_alerta(id_status);
ALTER TABLE alertas_phishing        ADD COLUMN IF NOT EXISTS id_status INTEGER REFERENCES estado_alerta(id_status);

-- 4) Opcional: asignar por defecto 'new' a registros existentes
UPDATE alertas_ddos             SET id_status = (SELECT id_status FROM estado_alerta WHERE codigo='new') WHERE id_status IS NULL;
UPDATE alertas_dos              SET id_status = (SELECT id_status FROM estado_alerta WHERE codigo='new') WHERE id_status IS NULL;
UPDATE alertas_fuerza_bruta     SET id_status = (SELECT id_status FROM estado_alerta WHERE codigo='new') WHERE id_status IS NULL;
UPDATE alertas_login_sospechoso SET id_status = (SELECT id_status FROM estado_alerta WHERE codigo='new') WHERE id_status IS NULL;
UPDATE alertas_phishing         SET id_status = (SELECT id_status FROM estado_alerta WHERE codigo='new') WHERE id_status IS NULL;

-- 5) (Recomendado) Índices para filtrar rápido por cliente + estado
CREATE INDEX IF NOT EXISTS idx_ddos_cli_status      ON alertas_ddos (id_cliente, id_status);
CREATE INDEX IF NOT EXISTS idx_dos_cli_status       ON alertas_dos (id_cliente, id_status);
CREATE INDEX IF NOT EXISTS idx_fb_cli_status        ON alertas_fuerza_bruta (id_cliente, id_status);
CREATE INDEX IF NOT EXISTS idx_login_cli_status     ON alertas_login_sospechoso (id_cliente, id_status);
CREATE INDEX IF NOT EXISTS idx_phish_cli_status     ON alertas_phishing (id_cliente, id_status);
