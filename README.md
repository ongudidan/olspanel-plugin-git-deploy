# OLSPanel Git Auto-Deploy Plugin

An official plugin for **OLSPanel** to automate continuous deployment of website repositories (from GitHub or any public/private Git host) directly onto your web server.

## Features
- **Frictionless GitHub App integration**: Direct OAuth flow without copy-pasting API tokens.
- **Webhooks & Auto-Deploy**: Automatically triggers deployment on repository push.
- **Auto-generated SSH Deploy Keys**: Secure integration with private git repositories.
- **Native Layout Integration**: Inherits OLSPanel design system, colors, modal styles, and validation banners.
- **Double click prevention and Loader states** on connection actions.

## Installation

*Note: The command line installation instructions must be run with root/administrative privileges (e.g. prefix with `sudo` or run directly as root depending on your system configuration).*

### Method 1: Direct Command Line (Recommended)
You can install the latest release directly:
```bash
install_cp_plugin https://github.com/ongudidan/olspanel-plugin-git-deploy/releases/latest/download/git_deploy.zip
```

Or target a specific version (e.g., `v1.0.0`):
```bash
install_cp_plugin https://github.com/ongudidan/olspanel-plugin-git-deploy/releases/download/v1.0.0/git_deploy_v1.0.0.zip
```

### Method 2: Manual Web UI
1. Go to the **Releases** page of this repository.
2. Download either the static `git_deploy.zip` or the version-specific `git_deploy_vX.Y.Z.zip` asset.
3. Log into your **OLSPanel Admin Control Panel**.
4. Go to **Plugins** -> **Install Plugin** and upload the downloaded zip.
5. Wait for the automatic reload to complete.

## Development & Packing
To pack the plugin manually, run this from the root of the repository:
```bash
zip -r git_deploy.zip git_deploy/ -x "*/.git*" -x "*.git*"
```

## Release Automation

### Option 1: Trigger via GitHub UI (Auto-increment)
1. Navigate to the **Actions** tab on GitHub.
2. Select the **Build and Release...** workflow.
3. Click the **Run workflow** button, select version level increment (`patch`, `minor`, `major`), and run.
4. The system will automatically compute the next version, tag it, and publish the release.

### Option 2: Manual Tag Push
If you prefer manual versioning:
```bash
git tag v1.0.0
git push origin v1.0.0
```
This triggers the Action to compile and publish that exact version.

