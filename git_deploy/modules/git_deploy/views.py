import os
import re
import hmac
import requests
import secrets
import hashlib
import json
import tempfile
import shutil
import subprocess
import time
from datetime import datetime
from threading import Thread
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.db import connection
from users.models import Domain
from users.database import get_user_data_by_id
from users.decorators import loginadminoruser
from django.contrib.auth import get_user_model

User = get_user_model()

def get_admin_user(request):
    """
    Retrieves authenticated admin user.
    Checks request.admin_user (populated by SeparateAdminSessionMiddleware from session_admin cookie),
    then checks request.user as a fallback.
    """
    admin_user = getattr(request, 'admin_user', None)
    if not admin_user and hasattr(request, 'user') and request.user.is_authenticated:
        if getattr(request.user, 'is_superuser', False) or getattr(request.user, 'is_staff', False):
            admin_user = request.user
        else:
            u_data = get_user_data_by_id(request.user.id)
            if u_data and u_data.get('whm') == 1:
                admin_user = request.user
        if admin_user:
            request.admin_user = admin_user
    return admin_user

def get_git_deploy_context(request):
    """
    Resolves the execution context for Git Deploy:
    - Identifies admin_user (from WHM admin session)
    - Identifies regular_user (from user session)
    - Detects if an admin is currently impersonating a client user
    - Determines active scope: 'admin' vs 'user'
    """
    admin_user = get_admin_user(request)
    regular_user = request.user if (hasattr(request, 'user') and request.user.is_authenticated) else None

    impersonated_user = getattr(request, 'impersonated_user', None)
    if not impersonated_user and hasattr(request, 'admin_session'):
        imp_id = request.admin_session.get('impersonated_user_id')
        if imp_id:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                impersonated_user = User.objects.get(id=imp_id)
            except User.DoesNotExist:
                impersonated_user = None

    if not impersonated_user and admin_user and regular_user and admin_user.id != regular_user.id:
        impersonated_user = regular_user

    is_impersonating = bool(impersonated_user)

    # Determine scope: 'admin' vs 'user'
    scope_param = request.GET.get('scope')

    if is_impersonating:
        # If admin is currently impersonating a client user, stay in user panel client mode
        # unless explicitly requested otherwise via ?scope=admin
        if scope_param == 'admin':
            active_scope = 'admin'
        else:
            active_scope = 'user'
    elif admin_user and not regular_user:
        # Admin logged in via WHM session only
        if scope_param == 'user':
            active_scope = 'user'
        else:
            active_scope = 'admin'
    elif admin_user and regular_user and admin_user.id == regular_user.id:
        # Admin logged into user panel as their own root/admin account
        if scope_param in ('admin', 'user'):
            active_scope = scope_param
        elif request.path.startswith('/whm/') or '/whm/' in request.META.get('HTTP_REFERER', ''):
            active_scope = 'admin'
        else:
            active_scope = 'user'
    else:
        # Regular client user only
        active_scope = 'user'

    # Save active scope in session if appropriate
    if hasattr(request, 'admin_session') and request.admin_session:
        request.admin_session['git_deploy_scope'] = active_scope
        request.admin_session.modified = True
    elif hasattr(request, 'session'):
        request.session['git_deploy_scope'] = active_scope

    if active_scope == 'admin' and admin_user:
        effective_user = admin_user
        is_admin_mode = True
        base_template = 'whm/base.html'
        # In admin mode, the top impersonation banner is not shown for the admin interface
        is_impersonating = False
    else:
        effective_user = impersonated_user or regular_user or admin_user
        is_admin_mode = False
        base_template = 'users/base.html'

    return {
        'admin_user': admin_user,
        'regular_user': regular_user,
        'effective_user': effective_user,
        'is_admin': is_admin_mode,
        'has_admin_rights': bool(admin_user),
        'is_impersonating': is_impersonating,
        'impersonated_user': impersonated_user,
        'scope': active_scope,
        'base_template': base_template,
    }

def get_authenticated_user(request):
    """Compatibility function: returns effective user based on resolved context"""
    ctx = get_git_deploy_context(request)
    return ctx['effective_user']


GITHUB_RECONNECT_MSG = "Your GitHub connection has expired. Open 'Connect GitHub', click Disconnect, then Authorize GitHub Account again."


def save_github_token(user_id, token_data):
    """Stores access token plus (for GitHub App user tokens) the refresh token and expiry."""
    from datetime import timedelta
    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')
    expires_in = token_data.get('expires_in')
    expires_at = datetime.now() + timedelta(seconds=int(expires_in) - 300) if expires_in else None
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user_id])
        if cursor.fetchone():
            cursor.execute(
                "UPDATE git_user_tokens SET token_value = %s, refresh_token = %s, expires_at = %s, created_at = %s WHERE userid_id = %s AND token_type = 'github'",
                [access_token, refresh_token, expires_at, datetime.now(), user_id])
        else:
            cursor.execute(
                "INSERT INTO git_user_tokens (userid_id, token_type, token_value, refresh_token, expires_at, created_at) VALUES (%s, 'github', %s, %s, %s, %s)",
                [user_id, access_token, refresh_token, expires_at, datetime.now()])


def refresh_github_token(user_id):
    """Exchanges the stored refresh token for a new access token. Returns new token or None."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT refresh_token FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user_id])
        row = cursor.fetchone()
        cursor.execute("SELECT setting_key, setting_value FROM git_settings WHERE setting_key IN ('github_client_id', 'github_client_secret')")
        conf = dict(cursor.fetchall())
    if not row or not row[0] or not conf.get('github_client_id') or not conf.get('github_client_secret'):
        return None
    try:
        res = requests.post("https://github.com/login/oauth/access_token", json={
            "client_id": conf['github_client_id'],
            "client_secret": conf['github_client_secret'],
            "grant_type": "refresh_token",
            "refresh_token": row[0],
        }, headers={"Accept": "application/json"}, timeout=15)
        data = res.json() if res.status_code == 200 else {}
    except Exception:
        return None
    if not data.get('access_token'):
        return None
    save_github_token(user_id, data)
    return data['access_token']


def get_valid_github_token(user_id, force_refresh=False):
    """
    Returns a usable GitHub token for the user, refreshing an expired GitHub App
    user token (ghu_, 8h lifetime) automatically when a refresh token is stored.
    Returns None if there is no token or it can no longer be refreshed.
    """
    with connection.cursor() as cursor:
        cursor.execute("SELECT token_value, refresh_token, expires_at FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user_id])
        row = cursor.fetchone()
    if not row:
        return None
    token, refresh_token, expires_at = row
    if force_refresh or (expires_at and expires_at <= datetime.now()):
        # Token known to be expired/rejected: refresh if possible, otherwise user must reconnect
        return refresh_github_token(user_id) if refresh_token else None
    return token


def get_domain_base_path(domain):
    """
    Returns the locked base folder assigned to a domain, e.g.
      /home/<owner>/public_html            (main domain)
      /home/<owner>/sub.example.com        (subdomain)
    If the domain document root was pointed deeper (e.g. /home/<owner>/public_html/public
    for Laravel), the base is still the domain folder (/home/<owner>/public_html) so the
    whole project can be deployed there.
    """
    doc_root = os.path.normpath(domain.path or '')
    owner = None
    try:
        owner = domain.userid.username if getattr(domain, 'userid', None) else None
    except Exception:
        owner = None
    if owner:
        home = f"/home/{owner}"
        if doc_root.startswith(home + os.sep):
            parts = doc_root[len(home) + 1:].split(os.sep)
            if parts and parts[0]:
                return os.path.join(home, parts[0])
    return doc_root


def resolve_deploy_path(domain, subdir='', legacy_full_path=''):
    """
    Builds the final deploy path strictly inside the domain's base folder.
    Returns (path, error). Users may only choose sub-folders; the base is non-negotiable.
    """
    base = get_domain_base_path(domain)
    if not base or not base.startswith('/home/'):
        return None, "This domain has no valid home directory assigned."

    subdir = (subdir or '').strip().replace('\\', '/')
    if not subdir and legacy_full_path:
        legacy = os.path.normpath(legacy_full_path.strip())
        if legacy == base:
            subdir = ''
        elif legacy.startswith(base + os.sep):
            subdir = legacy[len(base) + 1:]
        else:
            return None, f"Deploy path must be inside {base}"

    subdir = subdir.strip('/')
    if not subdir:
        return base, None
    if not re.fullmatch(r'[A-Za-z0-9._\-/ ]+', subdir):
        return None, "Folder name contains invalid characters."
    final = os.path.normpath(os.path.join(base, subdir))
    if final != base and not final.startswith(base + os.sep):
        return None, f"Deploy path must stay inside {base}"
    return final, None

def get_request_protocol(request):
    """
    Reliably detects https vs http for OLSPanel.
    In OLSPanel, port 2087 is HTTPS. Reverse proxies, Cloudflare, or local olspanelcp proxy
    may forward requests internally over HTTP to 127.0.0.1:8001.
    """
    if request.is_secure():
        return 'https'
    if request.META.get('HTTP_X_FORWARDED_PROTO', '').lower() == 'https':
        return 'https'
    if request.META.get('HTTP_X_FORWARDED_SSL', '').lower() == 'on':
        return 'https'
    if request.META.get('HTTP_X_FORWARDED_SCHEME', '').lower() == 'https':
        return 'https'
    # Check if host or server port is 2087 (OLSPanel default SSL port)
    host = request.get_host()
    if ':2087' in host or request.META.get('SERVER_PORT') == '2087':
        return 'https'
    # Check if request referer or origin was https
    origin = request.META.get('HTTP_ORIGIN', '') or request.META.get('HTTP_REFERER', '')
    if origin.startswith('https://'):
        return 'https'
    if request.scheme == 'https':
        return 'https'
    return 'http'


def normalize_git_url(url):
    """Normalizes various git URL formats (HTTPS, SSH, etc.) to organization/repo style"""
    url = url.strip().lower()
    if url.endswith('.git'):
        url = url[:-4]
    url = re.sub(r'^(https?://|git@|ssh://)', '', url)
    url = re.sub(r'^[^/:]+[:/]', '', url) # strip host prefix
    return url

def run_cmd_as_user_stream(username, cmd, cwd, log_func, env_vars=None):
    """Executes a command as a specific Linux user using sudo and streams its stdout/stderr"""
    full_cmd = ['sudo', '-H', '-u', username]
    
    # Inject Git SSH configuration if supplied
    if env_vars and 'GIT_SSH_COMMAND' in env_vars:
        full_cmd += ['env', f"GIT_SSH_COMMAND={env_vars['GIT_SSH_COMMAND']}"]
        
    full_cmd += cmd
    
    process = subprocess.Popen(
        full_cmd, 
        cwd=cwd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True, 
        bufsize=1
    )
    
    for line in iter(process.stdout.readline, ''):
        if line:
            log_func(line.rstrip('\r\n'))
            
    process.stdout.close()
    return_code = process.wait()
    return return_code


def run_contained_post_deploy_script(username, deploy_path, script_content, log_func, env_vars=None):
    """
    Executes custom post-deployment commands strictly confined within deploy_path.
    1. Executes under the unprivileged Linux username.
    2. Enforces cwd = deploy_path.
    3. Traps / overrides cd to prevent escaping outside deploy_path.
    4. Injects Node, PM2, Composer, PHP paths into PATH.
    5. Streams stdout and stderr line-by-line.
    6. Stops on first failure (set -eo pipefail).
    """
    if not script_content or not script_content.strip():
        return 0

    clean_deploy_path = os.path.normpath(deploy_path)

    # Resolve active Node binary directory if present
    node_bin_dirs = []
    nodejs_base = '/usr/local/olspanel/bin/nodejs'
    if os.path.exists(nodejs_base):
        try:
            for v in sorted(os.listdir(nodejs_base), reverse=True):
                cand = os.path.join(nodejs_base, v, 'bin')
                if os.path.isdir(cand):
                    node_bin_dirs.append(cand)
        except Exception:
            pass

    path_additions = ":".join(node_bin_dirs + ['/usr/local/bin', '/usr/bin', '/bin'])

    # Build the self-contained runner script
    runner_script = f"""#!/bin/bash
set -eo pipefail

export DEPLOY_ROOT="{clean_deploy_path}"
export HOME="/home/{username}"
export PATH="{path_additions}:$PATH"
export NODE_ENV="production"

cd "$DEPLOY_ROOT" || exit 1

# Override cd function to strictly contain execution within DEPLOY_ROOT
cd() {{
    builtin cd "$@" || return 1
    case "$PWD" in
        "$DEPLOY_ROOT"* ) ;;
        * )
            echo "ERROR: Navigation outside deployment root ($DEPLOY_ROOT) is restricted!" >&2
            builtin cd "$DEPLOY_ROOT"
            return 1
            ;;
    esac
}}

# User-defined commands follow:
{script_content.strip()}
"""

    # Write temporary runner script owned and executable by the user
    with tempfile.NamedTemporaryFile('w', delete=False, prefix='post_deploy_', suffix='.sh') as tf:
        tf.write(runner_script)
        script_path = tf.name

    try:
        # Give user read + execute permission
        subprocess.run(['sudo', 'chown', f"{username}:{username}", script_path], check=False)
        os.chmod(script_path, 0o750)

        # Run via run_cmd_as_user_stream
        cmd = ['bash', script_path]
        return run_cmd_as_user_stream(username, cmd, clean_deploy_path, log_func, env_vars)
    finally:
        if os.path.exists(script_path):
            try:
                os.remove(script_path)
            except Exception:
                pass


def create_pending_log(dep_id, commit_info=None):
    commit_hash = commit_info.get('hash') if commit_info else None
    commit_msg = commit_info.get('message') if commit_info else 'Manual Deployment'
    commit_author = commit_info.get('author') if commit_info else 'Dashboard User'
    
    with connection.cursor() as cursor:
        cursor.execute("""
            INSERT INTO git_deployment_logs (deployment_id, commit_hash, commit_message, commit_author, status, log_output, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, [dep_id, commit_hash, commit_msg, commit_author, 'pending', 'Starting deployment...\n', datetime.now()])
        return cursor.lastrowid

def deploy_worker(deployment_id, log_id, commit_info=None):
    """Threaded worker that handles checkout, pull, and package management steps"""
    
    # 1. Fetch deployment configuration
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT d.id, d.repo_url, d.branch, d.deploy_path, d.ssh_key, u.username, d.domain_id, d.auto_configured, d.post_deploy_script
            FROM git_deployments d
            JOIN domain dm ON d.domain_id = dm.id
            JOIN auth_user u ON dm.userid = u.id
            WHERE d.id = %s
        """, [deployment_id])
        row = cursor.fetchone()
        
    if not row:
        return
        
    dep_id, repo_url, branch, deploy_path, ssh_key, username, domain_id, auto_configured, post_deploy_script = row
    
    # Initialize state
    status = 'success'
    log_lines = []
    
    def log(message, with_timestamp=True):
        if with_timestamp:
            formatted = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        else:
            formatted = message
        log_lines.append(formatted)
        log_text = "\n".join(log_lines)
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE git_deployment_logs
                SET log_output = %s
                WHERE id = %s
            """, [log_text, log_id])
        
    log(f"Starting deployment for repository: {repo_url} (Branch: {branch})")
    
    # Create a temporary directory to host the deployment key securely
    key_dir = tempfile.mkdtemp()
    key_file = os.path.join(key_dir, 'deploy_key')
    env_vars = {}
    
    try:
        # Save custom SSH private key if repository is private
        if ssh_key and ssh_key.strip():
            # Apply ownership and permissions to the key directory so the standard user can traverse it
            subprocess.run(['sudo', 'chown', f"{username}:{username}", key_dir])
            os.chmod(key_dir, 0o700)
            
            with open(key_file, 'w', encoding='utf-8') as f:
                f.write(ssh_key.strip() + "\n")
            
            # Apply strict user permissions to the key
            os.chmod(key_file, 0o600)
            subprocess.run(['sudo', 'chown', f"{username}:{username}", key_file])
            env_vars['GIT_SSH_COMMAND'] = f"ssh -i {key_file} -o StrictHostKeyChecking=no"
            log("Configured SSH deployment key for private repository authentication.")
        
        # Ensure deployment directory exists
        if not os.path.exists(deploy_path):
            log(f"Creating deployment path: {deploy_path}")
            os.makedirs(deploy_path, exist_ok=True)
            subprocess.run(['sudo', 'chown', f"{username}:www-data", deploy_path])
            
        git_dir = os.path.join(deploy_path, '.git')
        
        # Run repository setup or pull
        if not os.path.exists(git_dir):
            log("Initializing new git repository in deployment path...")
            steps = [
                (['git', 'init'], "Initializing local repository"),
                (['git', 'remote', 'add', 'origin', repo_url], "Adding git origin remote"),
                (['git', 'fetch', 'origin'], "Fetching repository objects"),
                (['git', 'checkout', '-f', branch], f"Checking out target branch: {branch}"),
                (['git', 'branch', '--set-upstream-to=origin/' + branch, branch], "Linking local branch to upstream")
            ]
            
            for cmd, desc in steps:
                log(f"Running: {desc}...")
                code = run_cmd_as_user_stream(username, cmd, deploy_path, lambda msg: log(msg, with_timestamp=False), env_vars)
                if code != 0:
                    status = 'failed'
                    log(f"FAILED: {desc} (Exit code: {code})")
                    break
                else:
                    log(f"SUCCESS: {desc}")
        else:
            log("Existing git repository detected. Synchronizing...")
            steps = [
                (['git', 'fetch', '--all'], "Fetching all remote updates"),
                (['git', 'reset', '--hard', f"origin/{branch}"], f"Hard resetting local branch to origin/{branch}")
            ]
            
            for cmd, desc in steps:
                log(f"Running: {desc}...")
                code = run_cmd_as_user_stream(username, cmd, deploy_path, lambda msg: log(msg, with_timestamp=False), env_vars)
                if code != 0:
                    status = 'failed'
                    log(f"FAILED: {desc} (Exit code: {code})")
                    break
                else:
                    log(f"SUCCESS: {desc}")
                    
        # Pull submodules if present
        if status == 'success' and os.path.exists(os.path.join(deploy_path, '.gitmodules')):
            log("Initializing and updating submodules...")
            code = run_cmd_as_user_stream(username, ['git', 'submodule', 'update', '--init', '--recursive'], deploy_path, lambda msg: log(msg, with_timestamp=False), env_vars)
            if code != 0:
                log(f"Submodule check returned warning (Exit code: {code})")
            else:
                log("Submodules updated successfully.")

        # Execute post-deployment commands
        if status == 'success':
            if post_deploy_script and post_deploy_script.strip():
                log("Executing custom post-deployment commands inside working directory...")
                code = run_contained_post_deploy_script(username, deploy_path, post_deploy_script, lambda msg: log(msg, with_timestamp=False), env_vars)
                if code != 0:
                    status = 'failed'
                    log(f"FAILED: Custom post-deployment commands exited with status {code}")
                else:
                    log("SUCCESS: Custom post-deployment commands completed successfully.")
            else:
                # Default: Auto-reload Node.js / PM2 applications if registered on this deployment path
                try:
                    from users.models import Apps
                    node_app = Apps.objects.filter(domain_id=domain_id, path=deploy_path, type='node_js').first()
                    if not node_app:
                        node_app = Apps.objects.filter(path=deploy_path, type='node_js').first()

                    if node_app:
                        app_name = node_app.name or f"node-app-{node_app.id}"
                        log(f"Detected Node.js application '{app_name}' registered at this deploy path.")

                        # Run npm install if package.json exists
                        if os.path.exists(os.path.join(deploy_path, 'package.json')):
                            log("Running: npm install (--omit=dev)...")
                            code = run_cmd_as_user_stream(username, ['npm', 'install', '--omit=dev'], deploy_path, lambda msg: log(msg, with_timestamp=False), env_vars)
                            if code == 0:
                                log("SUCCESS: Dependencies installed.")
                            else:
                                log(f"WARNING: npm install finished with code {code}.")

                        # Trigger PM2 zero-downtime reload
                        from users.function import restart_node_app_under_pm2
                        log(f"Triggering PM2 zero-downtime reload for '{app_name}'...")
                        restart_res = restart_node_app_under_pm2(
                            username=username,
                            app_name=app_name,
                            app_path=deploy_path,
                            startup_file=node_app.startup_file,
                            node_version=node_app.version,
                            port=node_app.port,
                            env_str=node_app.env_variables,
                            app_mode=node_app.app_mode,
                            max_memory=node_app.max_memory
                        )
                        if restart_res.get('status') == 'success':
                            log(f"SUCCESS: Node.js application '{app_name}' reloaded successfully via PM2.")
                        else:
                            log(f"NOTICE: PM2 reload completed: {restart_res.get('message', 'done')}")
                except Exception as node_err:
                    log(f"Node.js post-deploy hook notice: {str(node_err)}")

    except Exception as ex:
        status = 'failed'
        log(f"CRITICAL ERROR: {str(ex)}")
    finally:
        # Clean up temporary SSH folder
        shutil.rmtree(key_dir, ignore_errors=True)
        
    log(f"Deployment complete. Status: {status.upper()}")
    
    # Save final status and output to the database
    log_text = "\n".join(log_lines)
    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE git_deployment_logs
            SET status = %s, log_output = %s
            WHERE id = %s
        """, [status, log_text, log_id])


@loginadminoruser
def gui_view(request):
    """Main dashboard interface"""
    ctx = get_git_deploy_context(request)
    user = ctx['effective_user']
    admin_user = ctx['admin_user']
    is_admin = ctx['is_admin']
    has_admin_rights = ctx['has_admin_rights']
    is_impersonating = ctx['is_impersonating']
    impersonated_user = ctx['impersonated_user']
    base_template = ctx['base_template']
    
    # Get standard domains for this user
    if user.is_superuser or is_admin:
        domains = Domain.objects.all().order_by('domain')
    else:
        domains = Domain.objects.filter(userid=user.id).order_by('domain')
    domains = list(domains)
    for dom in domains:
        dom.base_path = get_domain_base_path(dom)
        
    # Fetch existing deployments
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("""
                SELECT gd.id, d.domain, gd.domain_id, gd.repo_url, gd.branch, gd.deploy_path, gd.webhook_secret, gd.ssh_public_key, gd.auto_configured, gd.post_deploy_script, gd.created_at
                FROM git_deployments gd
                JOIN domain d ON gd.domain_id = d.id
            """)
        else:
            cursor.execute("""
                SELECT gd.id, d.domain, gd.domain_id, gd.repo_url, gd.branch, gd.deploy_path, gd.webhook_secret, gd.ssh_public_key, gd.auto_configured, gd.post_deploy_script, gd.created_at
                FROM git_deployments gd
                JOIN domain d ON gd.domain_id = d.id
                WHERE gd.userid_id = %s
            """, [user.id])
        columns = [col[0] for col in cursor.description]
        deployments = [dict(zip(columns, row)) for row in cursor.fetchall()]

    # Split each deployment path into locked base + editable sub-folder
    for dep in deployments:
        dom_obj = Domain.objects.filter(id=dep['domain_id']).first()
        base = get_domain_base_path(dom_obj) if dom_obj else ''
        path = os.path.normpath(dep['deploy_path'] or '')
        dep['base_path'] = base
        dep['deploy_subdir'] = path[len(base) + 1:] if base and path.startswith(base + os.sep) else ''
        dep['post_deploy_script'] = dep.get('post_deploy_script') or ''

    # Fetch last status log for each deployment
    for dep in deployments:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT status, commit_message, commit_hash, created_at
                FROM git_deployment_logs
                WHERE deployment_id = %s
                ORDER BY id DESC LIMIT 1
            """, [dep['id']])
            log_row = cursor.fetchone()
            if log_row:
                dep['last_status'] = log_row[0]
                dep['last_commit'] = log_row[1]
                dep['last_hash'] = log_row[2][:7] if log_row[2] else ''
                dep['last_date'] = log_row[3]
            else:
                dep['last_status'] = 'No Deploys'
                dep['last_commit'] = '-'
                dep['last_hash'] = ''
                dep['last_date'] = None

    # Check if user has a GitHub token saved
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user.id])
        has_github_token = cursor.fetchone() is not None

    # Fetch OAuth settings to see if configured
    settings = {}
    with connection.cursor() as cursor:
        cursor.execute("SELECT setting_key, setting_value FROM git_settings WHERE setting_key IN ('github_client_id', 'github_client_secret', 'github_app_slug')")
        for key, value in cursor.fetchall():
            settings[key] = value
            
    github_client_id = settings.get('github_client_id', '')
    github_client_secret = settings.get('github_client_secret', '')
    github_app_slug = settings.get('github_app_slug', '')
    oauth_configured = bool(github_client_id and github_client_secret)

    # Calculate webhook base URL
    host = request.get_host()
    protocol = get_request_protocol(request)
    webhook_url = f"{protocol}://{host}/module/git_deploy/webhook/"

    return render(request, 'git_deploy/gui.html', {
        'user': user,
        'domains': domains,
        'deployments': deployments,
        'webhook_url': webhook_url,
        'has_github_token': has_github_token,
        'oauth_configured': oauth_configured,
        'github_client_id': github_client_id,
        'github_client_secret': github_client_secret,
        'github_app_slug': github_app_slug,
        'base_template': base_template,
        'is_admin': is_admin,
        'has_admin_rights': has_admin_rights,
        'is_impersonating': is_impersonating,
        'impersonated_user': impersonated_user,
        'admin_user': admin_user,
        'scope': ctx['scope'],
    })


@loginadminoruser
def create_deployment_view(request):
    """API endpoint to create a new deployment configuration"""
    ctx = get_git_deploy_context(request)
    user = ctx['effective_user']
    admin_user = ctx['admin_user']
    is_admin = bool(admin_user)
    
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)
        
    domain_id = request.POST.get('domain_id')
    repo_url = request.POST.get('repo_url', '').strip()
    branch = request.POST.get('branch', 'main').strip() or 'main'
    deploy_path = request.POST.get('deploy_path', '').strip()
    post_deploy_script = request.POST.get('post_deploy_script', '').strip()
    auto_configure = request.POST.get('auto_configure') == 'true' or request.POST.get('auto_configure') == 'on'
    
    # Auto-detect repository type based on URL format
    if repo_url.startswith('git@') or repo_url.startswith('ssh://') or 'git@' in repo_url:
        repo_type = 'private'
    else:
        repo_type = 'public'
    
    if not domain_id or not repo_url:
        return JsonResponse({"status": "error", "message": "Domain and Repository URL are required"}, status=400)

    # Validate ownership of the selected domain
    if user.is_superuser or is_admin:
        domain = get_object_or_404(Domain, id=domain_id)
    else:
        domain = get_object_or_404(Domain, id=domain_id, userid=user.id)

    # Deploy path is locked to the domain's assigned folder; users only pick a sub-folder
    final_deploy_path, path_error = resolve_deploy_path(
        domain, request.POST.get('deploy_subdir', ''), deploy_path
    )
    if path_error:
        return JsonResponse({"status": "error", "message": path_error}, status=400)

    # Check for existing deployment on this domain
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM git_deployments WHERE domain_id = %s", [domain_id])
        if cursor.fetchone():
            return JsonResponse({"status": "error", "message": "A Git deployment is already configured for this domain"}, status=400)

    # Generate SSH deployment keys if repository is private
    ssh_key = None
    ssh_public_key = None
    if repo_type == 'private':
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, 'key')
            # Generate keypair securely without prompts
            subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-f', key_file], capture_output=True)
            if os.path.exists(key_file):
                with open(key_file, 'r', encoding='utf-8') as f:
                    ssh_key = f.read()
                with open(key_file + '.pub', 'r', encoding='utf-8') as f:
                    ssh_public_key = f.read()
            else:
                # Fallback to RSA if Ed25519 is somehow not supported
                subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '4096', '-N', '', '-f', key_file], capture_output=True)
                with open(key_file, 'r', encoding='utf-8') as f:
                    ssh_key = f.read()
                with open(key_file + '.pub', 'r', encoding='utf-8') as f:
                    ssh_public_key = f.read()

    # Generate webhook secret key
    webhook_secret = hashlib.sha256(os.urandom(32)).hexdigest()[:24]

    # Automated GitHub hook and key configuration via REST API
    github_error = None
    if auto_configure:
        # Check for token
        with connection.cursor() as cursor:
            cursor.execute("SELECT token_value FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user.id])
            token_row = cursor.fetchone()
            
        if not token_row:
            return JsonResponse({"status": "error", "message": "GitHub connection required for auto-configuration. Please connect first."}, status=400)
            
        github_token = get_valid_github_token(user.id)
        if not github_token:
            return JsonResponse({"status": "error", "message": GITHUB_RECONNECT_MSG}, status=400)
        owner, repo = parse_github_repo(repo_url)
        if not owner or not repo:
            return JsonResponse({"status": "error", "message": "Could not parse GitHub repository owner and name from the URL."}, status=400)
            
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        # 1. Add SSH Deploy Key if private
        if repo_type == 'private' and ssh_public_key:
            key_payload = {
                "title": f"OLSPanel Deploy Key ({domain.domain})",
                "key": ssh_public_key.strip(),
                "read_only": True
            }
            try:
                key_res = requests.post(f"https://api.github.com/repos/{owner}/{repo}/keys", json=key_payload, headers=headers, timeout=15)
                if key_res.status_code not in (200, 201):
                    res_json = key_res.json()
                    github_error = f"Failed to register Deploy Key on GitHub: {res_json.get('message', key_res.text)}"
            except Exception as ex:
                github_error = f"Error connecting to GitHub for Deploy Key: {str(ex)}"
                
        # 2. Add Push Webhook
        if not github_error:
            host = request.get_host()
            protocol = get_request_protocol(request)
            webhook_url = f"{protocol}://{host}/module/git_deploy/webhook/?secret={webhook_secret}"
            
            hook_payload = {
                "name": "web",
                "active": True,
                "events": ["push"],
                "config": {
                    "url": webhook_url,
                    "content_type": "json",
                    "secret": webhook_secret
                }
            }
            try:
                hook_res = requests.post(f"https://api.github.com/repos/{owner}/{repo}/hooks", json=hook_payload, headers=headers, timeout=15)
                if hook_res.status_code not in (200, 201):
                    res_json = hook_res.json()
                    if "already exists" not in res_json.get('message', '').lower():
                        github_error = f"Failed to register Webhook on GitHub: {res_json.get('message', hook_res.text)}"
            except Exception as ex:
                github_error = f"Error connecting to GitHub for Webhook: {str(ex)}"

    if github_error:
        return JsonResponse({"status": "error", "message": github_error}, status=400)

    # Determine proper user ID to own this deployment (domain's owner or active user)
    owner_id = getattr(domain, 'userid_id', None)
    if not owner_id and hasattr(domain, 'userid'):
        owner_id = getattr(domain.userid, 'id', None)
    if not owner_id:
        owner_id = user.id

    # Save details to MySQL
    with connection.cursor() as cursor:
        cursor.execute("""
            INSERT INTO git_deployments (userid_id, domain_id, repo_url, branch, deploy_path, webhook_secret, ssh_key, ssh_public_key, auto_configured, post_deploy_script, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, [owner_id, domain.id, repo_url, branch, final_deploy_path, webhook_secret, ssh_key, ssh_public_key, 1 if auto_configure else 0, post_deploy_script, datetime.now()])

    return JsonResponse({"status": "success", "message": "Deployment registered successfully"})


def parse_github_repo(url):
    """Extracts (owner, repo) from a GitHub URL"""
    url = url.strip()
    if url.endswith('.git'):
        url = url[:-4]
    
    ssh_match = re.search(r'github\.com[:/]([^/]+)/([^/]+)', url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)
        
    return None, None


@loginadminoruser
def manage_token_view(request):
    """Saves or deletes the user's GitHub Personal Access Token (PAT)"""
    user = get_authenticated_user(request)
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'delete':
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user.id])
            return JsonResponse({"status": "success", "message": "Token removed"})
            
        token = request.POST.get('token', '').strip()
        if not token:
            return JsonResponse({"status": "error", "message": "Token cannot be empty"}, status=400)
            
        # Validate token against GitHub API
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        try:
            res = requests.get("https://api.github.com/user", headers=headers, timeout=15)
            if res.status_code != 200:
                return JsonResponse({"status": "error", "message": "Invalid GitHub token (authentication failed)"}, status=400)
        except Exception as ex:
            return JsonResponse({"status": "error", "message": f"Could not connect to GitHub to validate token: {str(ex)}"}, status=400)
            
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user.id])
            if cursor.fetchone():
                cursor.execute("UPDATE git_user_tokens SET token_value = %s, refresh_token = NULL, expires_at = NULL, created_at = %s WHERE userid_id = %s AND token_type = 'github'", [token, datetime.now(), user.id])
            else:
                cursor.execute("INSERT INTO git_user_tokens (userid_id, token_type, token_value, created_at) VALUES (%s, 'github', %s, %s)", [user.id, token, datetime.now()])
                
        return JsonResponse({"status": "success", "message": "GitHub connection verified and token saved"})
        
    return JsonResponse({"status": "error", "message": "POST method required"}, status=400)


@loginadminoruser
def fetch_github_repos_view(request):
    """Fetches list of GitHub repositories using the saved PAT"""
    user = get_authenticated_user(request)
    with connection.cursor() as cursor:
        cursor.execute("SELECT token_value FROM git_user_tokens WHERE userid_id = %s AND token_type = 'github'", [user.id])
        row = cursor.fetchone()
        
    if not row:
        return JsonResponse({"status": "error", "message": "No GitHub token found. Please connect your account first."}, status=404)
        
    token = get_valid_github_token(user.id)
    if not token:
        return JsonResponse({"status": "error", "message": GITHUB_RECONNECT_MSG}, status=401)

    # Validate token; if GitHub rejects it, try one refresh before giving up
    try:
        check = requests.get("https://api.github.com/user", headers={
            "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"}, timeout=15)
        if check.status_code == 401:
            token = get_valid_github_token(user.id, force_refresh=True)
            if not token:
                return JsonResponse({"status": "error", "message": GITHUB_RECONNECT_MSG}, status=401)
    except Exception:
        pass

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    try:
        # Detect token type: GitHub App user tokens start with ghu_, fine-grained PAT with github_pat_
        token_prefix = token[:4] if len(token) >= 4 else token
        is_github_app_token = token_prefix in ("ghu_", "ghs_")

        repos_data = []

        if is_github_app_token:
            # GitHub App user tokens: /user/repos only shows repos where app is INSTALLED.
            # Also fetch repos via /user/installations to cover all installations.
            # Step 1: collect repos from /user/repos (visibility=all)
            page = 1
            while True:
                res = requests.get(
                    f"https://api.github.com/user/repos?per_page=100&sort=updated&visibility=all&page={page}",
                    headers=headers, timeout=15
                )
                if res.status_code != 200:
                    break
                page_data = res.json()
                if not page_data:
                    break
                repos_data.extend(page_data)
                if len(page_data) < 100:
                    break
                page += 1

            # Step 2: Fetch all App installations for this user, then get their repos
            inst_res = requests.get(
                "https://api.github.com/user/installations?per_page=100",
                headers=headers, timeout=15
            )
            if inst_res.status_code == 200:
                installations = inst_res.json().get("installations", [])
                existing_names = {r["full_name"] for r in repos_data}
                for inst in installations:
                    inst_id = inst.get("id")
                    ir_page = 1
                    while True:
                        ir = requests.get(
                            f"https://api.github.com/user/installations/{inst_id}/repositories?per_page=100&page={ir_page}",
                            headers=headers, timeout=15
                        )
                        if ir.status_code != 200:
                            break
                        ir_data = ir.json().get("repositories", [])
                        if not ir_data:
                            break
                        for r in ir_data:
                            if r.get("full_name") not in existing_names:
                                repos_data.append(r)
                                existing_names.add(r["full_name"])
                        if len(ir_data) < 100:
                            break
                        ir_page += 1
        else:
            # Traditional OAuth App token or PAT - /user/repos with visibility=all works normally
            page = 1
            while True:
                res = requests.get(
                    f"https://api.github.com/user/repos?per_page=100&sort=updated&visibility=all&page={page}",
                    headers=headers, timeout=15
                )
                if res.status_code != 200:
                    return JsonResponse({"status": "error", "message": "Failed to fetch repositories from GitHub"}, status=res.status_code)
                page_data = res.json()
                if not page_data:
                    break
                repos_data.extend(page_data)
                if len(page_data) < 100:
                    break
                page += 1

        repos = []
        for r in repos_data:
            repos.append({
                "name": r.get("name"),
                "full_name": r.get("full_name"),
                "clone_url": r.get("clone_url"),
                "ssh_url": r.get("ssh_url"),
                "private": r.get("private", False),
                "branch": r.get("default_branch", "main")
            })
        # Sort: private first, then alphabetical
        repos.sort(key=lambda x: (not x["private"], x["full_name"].lower()))
        return JsonResponse({"status": "success", "repos": repos, "token_type": token_prefix})
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"GitHub connection error: {str(e)}"}, status=500)


@loginadminoruser
def delete_deployment_view(request, dep_id):
    """Deletes a deployment configuration"""
    user = get_authenticated_user(request)
    is_admin = bool(get_admin_user(request))
    
    # Validate ownership
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("SELECT id FROM git_deployments WHERE id = %s", [dep_id])
        else:
            cursor.execute("SELECT id FROM git_deployments WHERE id = %s AND userid_id = %s", [dep_id, user.id])
            
        if not cursor.fetchone():
            return JsonResponse({"status": "error", "message": "Deployment config not found"}, status=404)
            
        # Delete configuration
        cursor.execute("DELETE FROM git_deployments WHERE id = %s", [dep_id])
        
    return JsonResponse({"status": "success", "message": "Deployment configuration deleted"})


@loginadminoruser
def update_deployment_view(request, dep_id):
    """Updates branch and deploy_path for an existing deployment"""
    user = get_authenticated_user(request)
    is_admin = bool(get_admin_user(request))
    
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)
        
    branch = request.POST.get('branch', 'main').strip() or 'main'
    deploy_path = request.POST.get('deploy_path', '').strip()
    deploy_subdir = request.POST.get('deploy_subdir', '')
    post_deploy_script = request.POST.get('post_deploy_script', '').strip()

    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("SELECT id, domain_id FROM git_deployments WHERE id = %s", [dep_id])
        else:
            cursor.execute("SELECT id, domain_id FROM git_deployments WHERE id = %s AND userid_id = %s", [dep_id, user.id])
        row = cursor.fetchone()

    if not row:
        return JsonResponse({"status": "error", "message": "Deployment config not found or access denied"}, status=404)

    domain = get_object_or_404(Domain, id=row[1])
    clean_path, path_error = resolve_deploy_path(domain, deploy_subdir, deploy_path)
    if path_error:
        return JsonResponse({"status": "error", "message": path_error}, status=400)

    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE git_deployments
            SET branch = %s, deploy_path = %s, post_deploy_script = %s
            WHERE id = %s
        """, [branch, clean_path, post_deploy_script, dep_id])
        
    return JsonResponse({"status": "success", "message": "Deployment configuration updated successfully"})


@loginadminoruser
def get_logs_view(request, dep_id):
    """Retrieves deployment history and outputs"""
    user = get_authenticated_user(request)
    is_admin = bool(get_admin_user(request))
    
    with connection.cursor() as cursor:
        # Check ownership
        if user.is_superuser or is_admin:
            cursor.execute("SELECT id FROM git_deployments WHERE id = %s", [dep_id])
        else:
            cursor.execute("SELECT id FROM git_deployments WHERE id = %s AND userid_id = %s", [dep_id, user.id])
            
        if not cursor.fetchone():
            return JsonResponse({"status": "error", "message": "Unauthorized"}, status=403)
            
        # Fetch log details
        cursor.execute("""
            SELECT id, commit_hash, commit_message, commit_author, status, log_output, created_at
            FROM git_deployment_logs
            WHERE deployment_id = %s
            ORDER BY id DESC LIMIT 50
        """, [dep_id])
        columns = [col[0] for col in cursor.description]
        logs = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
    return JsonResponse({"status": "success", "logs": logs})


@loginadminoruser
def log_stream_view(request, log_id):
    """Streams the log output for a given log ID in real-time"""
    user = get_authenticated_user(request)
    is_admin = bool(get_admin_user(request))
    
    # Verify ownership of the deployment associated with this log
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("""
                SELECT l.id FROM git_deployment_logs l
                JOIN git_deployments d ON l.deployment_id = d.id
                WHERE l.id = %s
            """, [log_id])
        else:
            cursor.execute("""
                SELECT l.id FROM git_deployment_logs l
                JOIN git_deployments d ON l.deployment_id = d.id
                WHERE l.id = %s AND d.userid_id = %s
            """, [log_id, user.id])
        if not cursor.fetchone():
            return HttpResponse("Unauthorized", status=403)
            
    def event_stream():
        last_pos = 0
        timeout_limit = 300  # 5 minutes safety timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout_limit:
            with connection.cursor() as cursor:
                cursor.execute("SELECT status, log_output FROM git_deployment_logs WHERE id = %s", [log_id])
                row = cursor.fetchone()
                
            if not row:
                break
                
            status, log_output = row
            log_output = log_output or ""
            
            if len(log_output) > last_pos:
                new_text = log_output[last_pos:]
                last_pos = len(log_output)
                yield new_text
                
            if status != 'pending':
                break
                
            time.sleep(0.2)
            
    return StreamingHttpResponse(event_stream(), content_type='text/plain')


@loginadminoruser
def trigger_manual_deploy_view(request, dep_id):
    """Triggers an instantaneous manual deployment in the background"""
    user = get_authenticated_user(request)
    is_admin = bool(get_admin_user(request))
    
    with connection.cursor() as cursor:
        if user.is_superuser or is_admin:
            cursor.execute("SELECT id FROM git_deployments WHERE id = %s", [dep_id])
        else:
            cursor.execute("SELECT id FROM git_deployments WHERE id = %s AND userid_id = %s", [dep_id, user.id])
            
        if not cursor.fetchone():
            return JsonResponse({"status": "error", "message": "Deployment config not found"}, status=404)
            
    # Create a pending log entry
    log_id = create_pending_log(dep_id)
    
    # Trigger background thread worker
    Thread(target=deploy_worker, args=(dep_id, log_id)).start()
    return JsonResponse({
        "status": "success", 
        "message": "Deployment triggered in background",
        "log_id": log_id
    })


@csrf_exempt
def webhook_view(request):
    """Main public API endpoint triggered by GitHub webhook push events"""
    if request.method != 'POST':
        return HttpResponse("POST request required", status=400)
        
    # Get URL secret key (or query secret parameter)
    secret_param = request.GET.get('secret')
    
    # Parse payload
    try:
        payload = json.loads(request.body)
    except Exception:
        return HttpResponse("Invalid JSON payload", status=400)
        
    ref = payload.get('ref', '')
    if not ref or not ref.startswith('refs/heads/'):
        return HttpResponse("Ignored: not a branch event", status=200)
        
    branch = ref.replace('refs/heads/', '')
    repository = payload.get('repository', {})
    
    # Extract URLs for matching
    clone_url = repository.get('clone_url', '')
    ssh_url = repository.get('ssh_url', '')
    html_url = repository.get('html_url', '')
    
    if not clone_url and not ssh_url:
        return HttpResponse("Invalid payload details", status=400)
        
    # Normalize repo name (e.g. owner/repo)
    normalized_incoming = normalize_git_url(clone_url or ssh_url or html_url)
    
    # Locate matching deployment configurations
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT id, repo_url, branch, webhook_secret
            FROM git_deployments
            WHERE branch = %s AND is_active = 1
        """, [branch])
        deployments = cursor.fetchall()
        
    matching_deploys = []
    for dep_id, repo_url, dep_branch, webhook_secret in deployments:
        # Check if Normalized Git URLs match
        if normalize_git_url(repo_url) == normalized_incoming:
            # Check secret parameters or signature header security
            signature = request.META.get('HTTP_X_HUB_SIGNATURE_256')
            if signature:
                try:
                    sha_name, sig_hex = signature.split('=')
                    mac = hmac.new(webhook_secret.encode(), request.body, hashlib.sha256)
                    if hmac.compare_digest(mac.hexdigest(), sig_hex):
                        matching_deploys.append(dep_id)
                except Exception:
                    pass
            elif secret_param and secret_param == webhook_secret:
                matching_deploys.append(dep_id)
                
    if not matching_deploys:
        return HttpResponse("No matching or verified git configurations found.", status=200)
        
    # Extract commit metadata
    head_commit = payload.get('head_commit', {})
    commit_info = {
        'hash': head_commit.get('id', ''),
        'message': head_commit.get('message', 'Automatic webhook push deployment'),
        'author': head_commit.get('author', {}).get('name', 'GitHub Push'),
    }
    
    # Trigger deployments in background
    for dep_id in matching_deploys:
        log_id = create_pending_log(dep_id, commit_info)
        Thread(target=deploy_worker, args=(dep_id, log_id, commit_info)).start()
        
    return HttpResponse(f"Autodeployment triggered for {len(matching_deploys)} configurations.", status=200)


@loginadminoruser
def manage_settings_view(request):
    """API endpoint to get or save global Git Auto-Deploy plugin configurations"""
    admin_user = get_admin_user(request)
    if not admin_user:
        return JsonResponse({"status": "error", "message": "Permission denied (Admin required)"}, status=403)
        
    if request.method == 'POST':
        client_id = request.POST.get('github_client_id', '').strip()
        client_secret = request.POST.get('github_client_secret', '').strip()
        
        with connection.cursor() as cursor:
            # Upsert github_client_id
            cursor.execute("SELECT id FROM git_settings WHERE setting_key = 'github_client_id'")
            if cursor.fetchone():
                cursor.execute("UPDATE git_settings SET setting_value = %s WHERE setting_key = 'github_client_id'", [client_id])
            else:
                cursor.execute("INSERT INTO git_settings (setting_key, setting_value) VALUES ('github_client_id', %s)", [client_id])
                
            # Upsert github_client_secret
            cursor.execute("SELECT id FROM git_settings WHERE setting_key = 'github_client_secret'")
            if cursor.fetchone():
                cursor.execute("UPDATE git_settings SET setting_value = %s WHERE setting_key = 'github_client_secret'", [client_secret])
            else:
                cursor.execute("INSERT INTO git_settings (setting_key, setting_value) VALUES ('github_client_secret', %s)", [client_secret])
                
        return JsonResponse({"status": "success", "message": "Global OAuth settings saved successfully"})
        
    # Get settings
    settings = {}
    with connection.cursor() as cursor:
        cursor.execute("SELECT setting_key, setting_value FROM git_settings")
        for key, value in cursor.fetchall():
            settings[key] = value
            
    return JsonResponse({
        "status": "success",
        "github_client_id": settings.get("github_client_id", ""),
        "github_client_secret": settings.get("github_client_secret", "")
    })


@loginadminoruser
def oauth_redirect_view(request):
    """Redirects the user to GitHub authorization page"""
    # Fetch Client ID from settings
    with connection.cursor() as cursor:
        cursor.execute("SELECT setting_value FROM git_settings WHERE setting_key = 'github_client_id'")
        row = cursor.fetchone()
        
    if not row or not row[0]:
        return HttpResponse("GitHub OAuth is not configured on this server. Contact administrator.", status=400)
        
    client_id = row[0]
    
    # Generate secure random state and store in session
    state = secrets.token_hex(16)
    request.session['github_oauth_state'] = state
    
    # Construct redirect URI
    host = request.get_host()
    protocol = get_request_protocol(request)
    redirect_uri = f"{protocol}://{host}/module/git_deploy/oauth/callback/"
    
    # Request repo and admin:repo_hook permissions
    authorize_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=repo,admin:repo_hook"
        f"&state={state}"
    )
    return redirect(authorize_url)


@loginadminoruser
def oauth_callback_view(request):
    """Callback receiver that exchanges OAuth auth code for an Access Token"""
    ctx = get_git_deploy_context(request)
    user = ctx['effective_user']
    code = request.GET.get('code')
    state = request.GET.get('state')
    session_state = request.session.get('github_oauth_state')
    
    # Clean state from session
    if 'github_oauth_state' in request.session:
        del request.session['github_oauth_state']
        
    if not code or not state or state != session_state:
        return HttpResponse("OAuth State verification failed or code missing. Please try again.", status=400)
        
    # Get client credentials
    with connection.cursor() as cursor:
        cursor.execute("SELECT setting_key, setting_value FROM git_settings WHERE setting_key IN ('github_client_id', 'github_client_secret')")
        settings = dict(cursor.fetchall())
        
    client_id = settings.get('github_client_id')
    client_secret = settings.get('github_client_secret')
    
    if not client_id or not client_secret:
        return HttpResponse("OAuth configurations missing on this server.", status=400)
        
    # Construct redirect URI
    host = request.get_host()
    protocol = get_request_protocol(request)
    redirect_uri = f"{protocol}://{host}/module/git_deploy/oauth/callback/"
    
    # Exchange code for access token
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri
    }
    headers = {
        "Accept": "application/json"
    }
    
    try:
        res = requests.post("https://github.com/login/oauth/access_token", json=payload, headers=headers, timeout=15)
        if res.status_code != 200:
            return HttpResponse(f"Token exchange failed: {res.text}", status=res.status_code)
            
        res_data = res.json()
        access_token = res_data.get('access_token')
        if not access_token:
            error_msg = res_data.get('error_description', 'No access token returned from GitHub.')
            return HttpResponse(f"GitHub OAuth error: {error_msg}", status=400)
            
        # Save token for user (incl. refresh token + expiry for GitHub App user tokens)
        save_github_token(user.id, res_data)
                
        scope_suffix = f"?scope={ctx['scope']}&" if ctx.get('scope') else "?"

        # GitHub App user tokens (ghu_) can only see private repos where the App is INSTALLED.
        # The OAuth authorize screen never shows the repository picker, so if the App is NOT yet
        # installed on this user's GitHub account, send them to the App's install page where they
        # choose "All repositories" or "Only select repositories". If it is already installed,
        # go straight back to the panel; users can change their selection any time via the
        # "Manage Repository Access" button. The token is already saved above.
        if access_token.startswith('ghu_'):
            with connection.cursor() as cursor:
                cursor.execute("SELECT setting_value FROM git_settings WHERE setting_key = 'github_app_slug'")
                slug_row = cursor.fetchone()
            app_slug = slug_row[0] if slug_row and slug_row[0] else ''
            if app_slug:
                installations = None
                try:
                    inst_res = requests.get(
                        "https://api.github.com/user/installations?per_page=100",
                        headers={
                            "Accept": "application/vnd.github+json",
                            "Authorization": f"Bearer {access_token}",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                        timeout=15,
                    )
                    if inst_res.status_code == 200:
                        installations = inst_res.json().get("installations", [])
                except Exception:
                    installations = None
                # Only redirect when we positively know there is no installation
                if installations is not None and len(installations) == 0:
                    return redirect(f"https://github.com/apps/{app_slug}/installations/new")

        return redirect(f'/module/git_deploy/gui/{scope_suffix}github_oauth=success')
    except Exception as e:
        return HttpResponse(f"Error during authentication: {str(e)}", status=500)


@loginadminoruser
def app_manifest_callback_view(request):
    """Callback receiver that exchanges the App Manifest code for App credentials"""
    admin_user = get_admin_user(request)
    if not admin_user:
        return HttpResponse("Permission denied (Admin required)", status=403)
        
    code = request.GET.get('code')
    if not code:
        return HttpResponse("Manifest conversion code is missing.", status=400)
        
    headers = {
        "Accept": "application/vnd.github+json"
    }
    
    try:
        # Request GitHub to convert manifest code to app credentials
        res = requests.post(f"https://api.github.com/app-manifests/{code}/conversions", headers=headers, timeout=15)
        if res.status_code not in (200, 201):
            return HttpResponse(f"GitHub App conversion failed: {res.text}", status=res.status_code)
            
        credentials = res.json()
        client_id = credentials.get("client_id")
        client_secret = credentials.get("client_secret")
        slug = credentials.get("slug", "")
        app_id = credentials.get("id", "")
        
        if not client_id or not client_secret:
            return HttpResponse("GitHub App Manifest did not return Client ID or Client Secret.", status=400)
            
        with connection.cursor() as cursor:
            # Upsert github_client_id
            cursor.execute("SELECT id FROM git_settings WHERE setting_key = 'github_client_id'")
            if cursor.fetchone():
                cursor.execute("UPDATE git_settings SET setting_value = %s WHERE setting_key = 'github_client_id'", [client_id])
            else:
                cursor.execute("INSERT INTO git_settings (setting_key, setting_value) VALUES ('github_client_id', %s)", [client_id])
                
            # Upsert github_client_secret
            cursor.execute("SELECT id FROM git_settings WHERE setting_key = 'github_client_secret'")
            if cursor.fetchone():
                cursor.execute("UPDATE git_settings SET setting_value = %s WHERE setting_key = 'github_client_secret'", [client_secret])
            else:
                cursor.execute("INSERT INTO git_settings (setting_key, setting_value) VALUES ('github_client_secret', %s)", [client_secret])
                
            # Upsert github_app_slug
            if slug:
                cursor.execute("SELECT id FROM git_settings WHERE setting_key = 'github_app_slug'")
                if cursor.fetchone():
                    cursor.execute("UPDATE git_settings SET setting_value = %s WHERE setting_key = 'github_app_slug'", [slug])
                else:
                    cursor.execute("INSERT INTO git_settings (setting_key, setting_value) VALUES ('github_app_slug', %s)", [slug])

            # Upsert github_app_id
            if app_id:
                cursor.execute("SELECT id FROM git_settings WHERE setting_key = 'github_app_id'")
                if cursor.fetchone():
                    cursor.execute("UPDATE git_settings SET setting_value = %s WHERE setting_key = 'github_app_id'", [str(app_id)])
                else:
                    cursor.execute("INSERT INTO git_settings (setting_key, setting_value) VALUES ('github_app_id', %s)", [str(app_id)])
                
        # Redirect user to install the App and choose "All repositories"
        # The response contains html_url like https://github.com/apps/{slug}
        app_html_url = credentials.get("html_url", "")
        if app_html_url:
            install_url = f"{app_html_url}/installations/new"
            return redirect(install_url)
        return redirect('/module/git_deploy/gui/?scope=admin&github_setup=success')
    except Exception as e:
        return HttpResponse(f"Error during app configuration: {str(e)}", status=500)


@loginadminoruser
def disconnect_github_view(request):
    """Disconnects the GitHub App and deletes settings from database"""
    admin_user = get_admin_user(request)
    if not admin_user:
        return JsonResponse({"status": "error", "message": "Permission denied (Admin required)"}, status=403)
        
    if request.method == 'POST':
        with connection.cursor() as cursor:
            # Delete credentials
            cursor.execute("DELETE FROM git_settings WHERE setting_key IN ('github_client_id', 'github_client_secret', 'github_app_slug', 'github_app_id')")
            # Also clean up all user tokens
            cursor.execute("DELETE FROM git_user_tokens WHERE token_type = 'github'")
            
        return JsonResponse({"status": "success", "message": "GitHub App disconnected successfully"})
        
    return JsonResponse({"status": "error", "message": "Invalid request method"}, status=400)
