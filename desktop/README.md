# IASG desktop app

A small Electron app that runs the packaged IASG stack in Docker and shows the
dashboard in its own window. It holds no IASG code itself: the services come
from prebuilt images, so a new release reaches users without a new installer.

## What it does on launch

1. Checks that Docker Desktop is installed and running. If it is not, the app
   waits and carries on by itself once Docker is up, with no Retry needed:
   - **Not installed:** step-by-step setup, with a direct download of the
     installer for this machine (Apple Silicon or Intel Mac, Windows x64 or
     ARM, detected even when the app itself runs under Rosetta or emulation).
     On Windows the WSL 2 requirement is explained before the steps, with fixes
     for the two usual failures: WSL out of date and virtualization disabled in
     the firmware.
   - **Installed but stopped:** the app opens Docker Desktop once and waits.
2. Asks GitHub for the latest release. If it is newer than the version it ran
   last, it downloads that release's `docker-compose.release.yml` and pulls the
   images. The new version is only switched to once the pull succeeds;
   otherwise the previous version keeps running.
3. Runs `docker compose -p iasg up -d` and waits for the dashboard's
   `/api/health`, then loads http://127.0.0.1:5177.
4. On quit, runs `docker compose down` (without `-v`, so data is kept).

Offline, it runs the last version it downloaded. State lives in the app's
user-data folder (`~/Library/Application Support/IASG` on macOS,
`%APPDATA%\IASG` on Windows): `state.json` and `compose.yml`.

The app does not update itself. When a release is newer than the app, the
**IASG** menu shows a "Download Launcher" item linking to it; the app only
needs reinstalling when this folder changes.

## Making a release

1. Merge to `main`.
2. Tag and push:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. Watch the **Actions** tab. [`release.yml`](../.github/workflows/release.yml)
   builds the five images (amd64 + arm64) into GHCR, builds the `.dmg`,
   `.exe`, `.AppImage`, `.deb` and `.pacman`, attaches them and the compose file to a release, and only then
   publishes it. Expect 15–30 minutes.
4. **First release only:** GHCR packages start out private, and the app cannot
   pull them until they are public. The repository owner opens each of the
   five `iasg-*` packages (profile → Packages) → Package settings → Change
   visibility → Public.

## Developing the app

```bash
cd desktop
npm install
npm start
```

If you run this from a VS Code terminal, unset `ELECTRON_RUN_AS_NODE` first
(`env -u ELECTRON_RUN_AS_NODE npm start`) — VS Code sets it, and it makes
Electron start as plain Node.

Testing without publishing a release:

| Variable | Effect |
|---|---|
| `IASG_RELEASE_API` | URL (or `file://` path) of a release JSON to use instead of GitHub's `releases/latest` |
| `IASG_REGISTRY` | Image registry prefix, e.g. `local` for images built with `docker build -t local/iasg-gateway:0.1.0 gateway` |
| `IASG_SKIP_PULL` | Skip `docker compose pull`, for images that only exist locally |
| `IASG_DOCKER` | Docker binary to run instead of `docker`. A path that does not exist shows the not-installed screen on a machine that has Docker. |

Build an installer locally with `npm run dist:mac` (or `dist:win` on Windows);
output goes to `desktop/dist/`.

## Ports

The packaged stack publishes only these, all on 127.0.0.1 (the dashboard has
no login): dashboard 5177, gateway 8082, demo web 5175, demo API 5002. Postgres
and Redis are not published. Stop the source-checkout stack
(`docker compose -f infra/docker-compose.yml stop`) before launching the app,
since they share these ports.
