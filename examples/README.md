# Client Configuration Examples

Copy-paste configs that point each package manager at a Jōei instance running
on `http://localhost:8080` (adjust host/port to your deployment).

| Ecosystem | File | Where it goes |
|---|---|---|
| pip | [`pip/pip.conf`](pip/pip.conf) | `~/.pip/pip.conf` (Linux/macOS), `%APPDATA%\pip\pip.ini` (Windows) |
| npm | [`npm/.npmrc`](npm/.npmrc) | project root or `~/.npmrc` |
| Yarn | [`yarn/.yarnrc.yml`](yarn/.yarnrc.yml) | project root (Berry); see file for Classic |
| Maven | [`maven/settings.xml`](maven/settings.xml) | `~/.m2/settings.xml` |
| Gradle | [`gradle/init.gradle.kts`](gradle/init.gradle.kts) | `~/.gradle/init.d/` |
| Bundler | [`bundler/README.md`](bundler/README.md) | per-project `bundle config` |
| Docker | [`docker/daemon.json`](docker/daemon.json) | `/etc/docker/daemon.json` |

Also here:

- [`allowlist.txt`](allowlist.txt) — supply-chain allowlist file format, wired
  via `supply_chain.allowlist_path`.

For running Jōei itself, start from the repository's
[`docker-compose.yaml`](../docker-compose.yaml) and
[`config.yaml`](../config.yaml); every key is documented in
[`docs/configuration.md`](../docs/configuration.md).
