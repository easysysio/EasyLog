#!/bin/sh
# Build the EasyLog documentation site and publish it to easylog.easysys.io.
#
# Mirrors EasyWAF/deploy-docs.sh and EasySYS-web/deploy.sh: pull, build with
# mkdocs, replace what is served. Run it on the host that serves the site; the
# web server's easylog.easysys.io vhost should point at the target directory.
#
# Usage: ./deploy-docs.sh [TARGET]    (default /var/www/easylog)
set -e

TARGET=${1:-/var/www/easylog}

# The target is removed wholesale below, so refuse anything that isn't a
# dedicated directory.
case "$TARGET" in
  /|/var|/var/www|/var/www/) echo "Refusing to deploy over $TARGET" >&2; exit 1 ;;
esac

cd "$(dirname "$0")"

echo "Building the EasyLog documentation site"
git pull
# Built before the old site is touched: a failed build leaves the live site up.
mkdocs build --strict

rm -rf "$TARGET"
cp -r site "$TARGET"
echo "Deployed to $TARGET"
