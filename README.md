# OLSPanel Git Auto-Deploy Plugin

An official plugin for **OLSPanel** to automate continuous deployment of website repositories (from GitHub or any public/private Git host) directly onto your web server.

## Features
- **Frictionless GitHub App integration**: Direct OAuth flow without copy-pasting API tokens.
- **Webhooks & Auto-Deploy**: Automatically triggers deployment on repository push.
- **Auto-generated SSH Deploy Keys**: Secure integration with private git repositories.
- **Native Layout Integration**: Inherits OLSPanel design system, colors, modal styles, and validation banners.
- **Double click prevention and Loader states** on connection actions.

## Installation
1. Download the `git_deploy.zip` from the latest release in this repository.
2. Log into your **OLSPanel Admin Control Panel**.
3. Go to **Plugins** -> **Install Plugin** and upload `git_deploy.zip`.
4. Wait for the automatic reload to complete.

## Development & Packing
To pack the plugin manually, run:
```bash
zip -r git_deploy.zip git_deploy/
```

## Release Automation
Simply push a version tag to trigger the automatic build and release:
```bash
git tag v1.0.0
git push origin v1.0.0
```
The GitHub Action will compile and publish the asset.

