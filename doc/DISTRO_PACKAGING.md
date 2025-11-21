# Recommendations for distribution packaging

If you want to package the software for distribution, a few adjustments/patches are recommended:

- You probably want to install the systemd units under `/lib/systemd/system/` or similar, instead of `/etc`.

- The build environment variable `HTTUN_CONF_PREFIX` sets the prefix for the configuration files.
  In a plain `cargo build` this will default to `/` meaning that `/etc/httun/` will be the place for the configuration files.
  If you use the `build.sh` script, the prefix will be set to `/opt/httun/` instead.
  Meaning that the configuration files will be placed into `/opt/httun/etc/httun/`.

- Adjust the install prefix from `/opt` to something else that makes more sense for your distribution.
