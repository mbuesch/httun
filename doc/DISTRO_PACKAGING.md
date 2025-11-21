# Recommendations for distribution packaging

If you want to package the software for distribution, a few adjustments/patches are recommended:

- You probably want to install the systemd units under `/lib/systemd/system/` or similar, instead of `/etc`.

- TODO: Allow config files in /etc

- Adjust the install prefix from `/opt` to something else that makes more sense for your distribution.
