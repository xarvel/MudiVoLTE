#!/bin/sh
# Tests of the web pages that run outside the router: the GL admin panel page
# with Vue 2 in node, and the LuCI page with LuCI's modules as stubs. Vue goes
# into a temporary directory, not the project.
#   package/tests/run.sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
deps=$(mktemp -d)
trap 'rm -rf "$deps"' EXIT
(cd "$deps" && npm install --no-audit --no-fund --silent vue@2.7.16 vue-server-renderer@2.7.16 >/dev/null)
NODE_PATH=$deps/node_modules node "$here/gl-view.test.js"
node "$here/luci-view.test.js"
