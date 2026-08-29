#!/bin/bash
# Publish the Sphinx docs to Cloudflare Pages at ebpf.kvcache.io.
#
# GitHub Pages cannot serve this repository: the enterprise account has
# Actions restricted, and GitHub builds every Pages site -- branch-based
# ones included -- through the pages-build-deployment Action, so nothing is
# ever published. Cloudflare already serves DNS for kvcache.io, so it builds
# and serves the same docs/ tree without needing Actions at all.
#
# This uses Pages "direct upload": the site is built here and pushed up, so
# it does NOT rebuild on git push. Re-run this after changing docs/.
#
# Requires an API token with, at minimum:
#   Account -> Cloudflare Pages -> Edit
#   Zone    -> DNS              -> Edit   (zone: kvcache.io)
# Create one at https://dash.cloudflare.com/profile/api-tokens then:
#   export CLOUDFLARE_API_TOKEN=...
#   export CLOUDFLARE_ACCOUNT_ID=...     # the account holding the kvcache.io zone
#   ./docs/deploy-cloudflare-pages.sh
set -eu

ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
ZONE_NAME="kvcache.io"
DOMAIN="ebpf.kvcache.io"
PROJECT="${PAGES_PROJECT:-ebpf-syscall}"

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/docs/_build/html"
api="https://api.cloudflare.com/client/v4"
auth="Authorization: Bearer ${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"

jq_ok() { python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get('success') else 1)"; }
say() { printf '\n== %s\n' "$1"; }

say "building docs"
rm -rf "$out"
python3 -m sphinx -b html -W --keep-going "$here/docs" "$out"

say "creating Pages project '$PROJECT' (ignored if it already exists)"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"name\":\"$PROJECT\",\"production_branch\":\"main\"}" \
	"$api/accounts/$ACCOUNT_ID/pages/projects" >/dev/null || true

say "uploading site"
CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID" npx --yes wrangler@latest pages deploy "$out" \
	--project-name="$PROJECT" --branch=main --commit-dirty=true

say "clearing DNS records that would shadow the Pages hostname"
zone_id=$(curl -s -H "$auth" "$api/zones?name=$ZONE_NAME" |
	python3 -c "import json,sys;print(json.load(sys.stdin)['result'][0]['id'])")
curl -s -H "$auth" "$api/zones/$zone_id/dns_records?name=$DOMAIN" |
	python3 -c "import json,sys;[print(r['id']) for r in json.load(sys.stdin).get('result',[])]" |
	while read -r rec; do
		echo "  deleting $rec"
		curl -s -X DELETE -H "$auth" "$api/zones/$zone_id/dns_records/$rec" >/dev/null
	done

say "attaching $DOMAIN to the Pages project"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"name\":\"$DOMAIN\"}" \
	"$api/accounts/$ACCOUNT_ID/pages/projects/$PROJECT/domains" >/dev/null || true

say "pointing $DOMAIN at $PROJECT.pages.dev"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"type\":\"CNAME\",\"name\":\"$DOMAIN\",\"content\":\"$PROJECT.pages.dev\",\"proxied\":true}" \
	"$api/zones/$zone_id/dns_records" | jq_ok ||
	echo "  (record may already exist -- check the dashboard)"

say "done -- https://$DOMAIN"
echo "Certificates can take a few minutes on first publish."
