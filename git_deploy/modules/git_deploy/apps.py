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

        # Hook into WHM plugins list API view in-memory to dynamically discover and register all local modules
        try:
            from whm import views as whm_views
            from django.http import JsonResponse
            import os
            import json

            original_api_plugins = whm_views.api_plugins

            def patched_api_plugins(request):
                response = original_api_plugins(request)
                if isinstance(response, JsonResponse):
                    try:
                        data = json.loads(response.content.decode('utf-8'))
                        if data.get('success'):
                            plugins = data.get('plugins', [])
                            existing_paths = {p.get('path') for p in plugins if p.get('path')}
                            existing_names = {p.get('name', '').lower() for p in plugins}

                            modules_dir = "/usr/local/olspanel/mypanel/modules"

                            known_meta = {
                                "pm2": {
                                    "name": "PM2/Node.js Manager",
                                    "category": "Terminal",
                                    "image": "/media/icon/pm2.svg",
                                    "url": "https://github.com/ongudidan/olspanel-plugin-pm2/releases/latest/download/pm2.zip"
                                },
                                "git_deploy": {
                                    "name": "Git Deployment Manager",
                                    "category": "Terminal",
                                    "image": "/media/icon/git_deploy.svg",
                                    "url": "https://github.com/ongudidan/olspanel-plugin-git-deploy/releases/latest/download/git_deploy.zip"
                                },
                                "terminal": {
                                    "name": "Terminal",
                                    "category": "Terminal",
                                    "image": "/media/icon/terminal.svg",
                                    "url": ""
                                }
                            }

                            terminal_cat_id = 3
                            for p in plugins:
                                if p.get('category', '').lower() == 'terminal':
                                    terminal_cat_id = p.get('category_id', 3)
                                    break

                            if os.path.exists(modules_dir):
                                for name in os.listdir(modules_dir):
                                    mod_path = os.path.join(modules_dir, name)
                                    if os.path.isdir(mod_path) and name not in ['.', '..', '__pycache__']:
                                        meta = known_meta.get(name, {})
                                        display_name = meta.get("name") or name.replace('_', ' ').replace('-', ' ').title()
                                        
                                        # Skip duplicates by path, name, or slug name
                                        if mod_path not in existing_paths and display_name.lower() not in existing_names and name.lower() not in existing_names:
                                            category = meta.get("category") or "Terminal"
                                            url_val = meta.get("url") or ""

                                            # Find image
                                            icon_path = meta.get("image")
                                            if not icon_path:
                                                if os.path.exists(f"/usr/local/olspanel/mypanel/media/icon/{name}.svg"):
                                                    icon_path = f"/media/icon/{name}.svg"
                                                elif os.path.exists(f"/usr/local/olspanel/mypanel/media/icon/{name}.png"):
                                                    icon_path = f"/media/icon/{name}.png"
                                                else:
                                                    icon_path = "/media/icon/extension.svg"

                                            custom_plugin = {
                                                "id": 100 + len(plugins),
                                                "name": display_name,
                                                "category": category,
                                                "category_id": terminal_cat_id,
                                                "type": "free",
                                                "url": url_val,
                                                "path": mod_path,
                                                "image": icon_path,
                                                "pre_build_path": "",
                                                "is_installed": True,
                                                "license_valid": True
                                            }
                                            plugins.append(custom_plugin)
                                            existing_paths.add(mod_path)
                                            existing_names.add(display_name.lower())

                            data['plugins'] = plugins
                            data['count'] = len(plugins)
                            response.content = json.dumps(data).encode('utf-8')
                    except Exception:
                        pass
                return response

            whm_views.api_plugins = patched_api_plugins
            print("[GitDeploy] Successfully registered in-memory plugin auto-discovery hook.")
        except Exception as patch_err:
            print(f"[GitDeploy] Plugin auto-discovery hook registration warning: {patch_err}")
