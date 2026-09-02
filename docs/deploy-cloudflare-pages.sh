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
KVIO_DOMAIN="kvio.kvcache.io"
KVIO_PROJECT="${KVIO_PAGES_PROJECT:-kvio}"
KVSPILL_DOMAIN="kvspill.kvcache.io"
KVSPILL_PROJECT="${KVSPILL_PAGES_PROJECT:-kvspill}"

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/docs/_build/html"
api="https://api.cloudflare.com/client/v4"
auth="Authorization: Bearer ${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"

jq_ok() { python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get('success') else 1)"; }
say() { printf '\n== %s\n' "$1"; }
# Cloudflare only gives a project <name>.pages.dev when that name is globally
# free; otherwise it suffixes (kvio -> kvio-dsc.pages.dev). Read it back rather
# than assuming, or the CNAME points at a host that does not exist.
project_subdomain() {
	curl -s -H "$auth" "$api/accounts/$ACCOUNT_ID/pages/projects/$1" |
		python3 -c "import json,sys;print(json.load(sys.stdin)['result']['subdomain'])"
}


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

sub=$(project_subdomain "$PROJECT")
say "pointing $DOMAIN at $sub"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"type\":\"CNAME\",\"name\":\"$DOMAIN\",\"content\":\"$sub\",\"proxied\":true}" \
	"$api/zones/$zone_id/dns_records" | jq_ok ||
	echo "  (record may already exist -- check the dashboard)"

# --- kvio.kvcache.io -------------------------------------------------------
# The kvio showcase gets its own hostname serving the page directly at the
# root, rather than a redirect into the docs site. The standalone showcase
# pages cross-link to each other by filename, so ship the set and make kvio
# the index.
say "publishing the kvio microsite"
kvio_out="$here/docs/_build/kvio"
rm -rf "$kvio_out"; mkdir -p "$kvio_out"
cp "$here/docs/kvio.html" "$kvio_out/index.html"
for f in kvio kvio-loadpath kvio-perfetto gnn-readamp; do
	[ -f "$here/docs/$f.html" ] && cp "$here/docs/$f.html" "$kvio_out/"
done
[ -d "$here/docs/img" ] && cp -r "$here/docs/img" "$kvio_out/"
printf '%s\n' "$KVIO_DOMAIN" > "$kvio_out/CNAME"

curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"name\":\"$KVIO_PROJECT\",\"production_branch\":\"main\"}" \
	"$api/accounts/$ACCOUNT_ID/pages/projects" >/dev/null || true
CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID" npx --yes wrangler@latest pages deploy "$kvio_out" \
	--project-name="$KVIO_PROJECT" --branch=main --commit-dirty=true

say "clearing DNS records that would shadow $KVIO_DOMAIN"
curl -s -H "$auth" "$api/zones/$zone_id/dns_records?name=$KVIO_DOMAIN" |
	python3 -c "import json,sys;[print(r['id']) for r in json.load(sys.stdin).get('result',[])]" |
	while read -r rec; do
		echo "  deleting $rec"
		curl -s -X DELETE -H "$auth" "$api/zones/$zone_id/dns_records/$rec" >/dev/null
	done

say "attaching $KVIO_DOMAIN to $KVIO_PROJECT"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"name\":\"$KVIO_DOMAIN\"}" \
	"$api/accounts/$ACCOUNT_ID/pages/projects/$KVIO_PROJECT/domains" >/dev/null || true
kvio_sub=$(project_subdomain "$KVIO_PROJECT")
say "pointing $KVIO_DOMAIN at $kvio_sub"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"type\":\"CNAME\",\"name\":\"$KVIO_DOMAIN\",\"content\":\"$kvio_sub\",\"proxied\":true}" \
	"$api/zones/$zone_id/dns_records" | jq_ok ||
	echo "  (record may already exist -- check the dashboard)"

# --- kvspill.kvcache.io ---------------------------------------------------
# Serve the standalone kvspill page at the hostname root. Do not use a
# redirect: the dedicated hostname should remain useful if the main docs URL
# layout changes.
say "publishing the kvspill microsite"
kvspill_out="$here/docs/_build/kvspill"
rm -rf "$kvspill_out"; mkdir -p "$kvspill_out"
cp "$here/docs/kvspill.html" "$kvspill_out/index.html"
printf '%s\n' "$KVSPILL_DOMAIN" > "$kvspill_out/CNAME"

curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"name\":\"$KVSPILL_PROJECT\",\"production_branch\":\"main\"}" \
	"$api/accounts/$ACCOUNT_ID/pages/projects" >/dev/null || true
CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID" npx --yes wrangler@latest pages deploy "$kvspill_out" \
	--project-name="$KVSPILL_PROJECT" --branch=main --commit-dirty=true

say "clearing DNS records that would shadow $KVSPILL_DOMAIN"
curl -s -H "$auth" "$api/zones/$zone_id/dns_records?name=$KVSPILL_DOMAIN" |
	python3 -c "import json,sys;[print(r['id']) for r in json.load(sys.stdin).get('result',[])]" |
	while read -r rec; do
		echo "  deleting $rec"
		curl -s -X DELETE -H "$auth" "$api/zones/$zone_id/dns_records/$rec" >/dev/null
	done

say "attaching $KVSPILL_DOMAIN to $KVSPILL_PROJECT"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"name\":\"$KVSPILL_DOMAIN\"}" \
	"$api/accounts/$ACCOUNT_ID/pages/projects/$KVSPILL_PROJECT/domains" >/dev/null || true
kvspill_sub=$(project_subdomain "$KVSPILL_PROJECT")
say "pointing $KVSPILL_DOMAIN at $kvspill_sub"
curl -s -X POST -H "$auth" -H 'Content-Type: application/json' \
	--data "{\"type\":\"CNAME\",\"name\":\"$KVSPILL_DOMAIN\",\"content\":\"$kvspill_sub\",\"proxied\":true}" \
	"$api/zones/$zone_id/dns_records" | jq_ok ||
	echo "  (record may already exist -- check the dashboard)"

say "done -- https://$DOMAIN, https://$KVIO_DOMAIN, and https://$KVSPILL_DOMAIN"
echo "Certificates can take a few minutes on first publish."
