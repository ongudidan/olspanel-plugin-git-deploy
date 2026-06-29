from django.apps import AppConfig
from django.db import connection

class GitDeployConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'modules.git_deploy'

    def ready(self):
        # Dynamically ensure required deployment tables exist in MySQL
        try:
            with connection.cursor() as cursor:
                # 1. git_deployments table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS git_deployments (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        userid_id INT NOT NULL,
                        domain_id INT NOT NULL,
                        repo_url VARCHAR(255) NOT NULL,
                        branch VARCHAR(50) NOT NULL DEFAULT 'main',
                        deploy_path VARCHAR(255) NOT NULL,
                        webhook_secret VARCHAR(100) NOT NULL,
                        ssh_key TEXT NULL,
                        ssh_public_key TEXT NULL,
                        is_active TINYINT(1) NOT NULL DEFAULT 1,
                        created_at DATETIME NOT NULL,
                        FOREIGN KEY (userid_id) REFERENCES auth_user(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                
                # 2. git_deployment_logs table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS git_deployment_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        deployment_id INT NOT NULL,
                        commit_hash VARCHAR(50) NULL,
                        commit_message VARCHAR(255) NULL,
                        commit_author VARCHAR(100) NULL,
                        status VARCHAR(20) NOT NULL,
                        log_output LONGTEXT NULL,
                        created_at DATETIME NOT NULL,
                        FOREIGN KEY (deployment_id) REFERENCES git_deployments(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                
                # 3. git_user_tokens table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS git_user_tokens (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        userid_id INT NOT NULL,
                        token_type VARCHAR(20) NOT NULL,
                        token_value TEXT NOT NULL,
                        created_at DATETIME NOT NULL,
                        FOREIGN KEY (userid_id) REFERENCES auth_user(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                
                # 4. git_settings table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS git_settings (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        setting_key VARCHAR(50) UNIQUE NOT NULL,
                        setting_value TEXT NOT NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                # 5. Add auto_configured column if not exists (migration)
                try:
                    cursor.execute("ALTER TABLE git_deployments ADD COLUMN auto_configured TINYINT(1) NOT NULL DEFAULT 0")
                except Exception:
                    pass  # Column already exists
        except Exception as e:
            print(f"[GitDeploy] Database initialization warning: {e}")
