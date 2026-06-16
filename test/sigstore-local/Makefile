# Local sigstore harness. Rootless Podman by default; override COMPOSE to use
# docker compose. Not part of the strike trusted binary.
COMPOSE   ?= podman compose
ISSUER    := https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore
DISCOVERY := $(ISSUER)/.well-known/openid-configuration
CADDY_ROOT := pki/caddy-root.crt

.PHONY: keys up down clean caddy-root check-issuer preflight token tsa-certchain rekor-pubkey ctlog-pubkey conformance

keys: pki/rekor-ed25519.pem pki/rekor-ed25519-pub.pem pki/fulcio-root.crt pki/fulcio-root.key pki/ctfe.key pki/ctfe-pub.pem ## generate signing keys: rekor ed25519, the Fulcio fileca root, and the CT log (ctfe) key

pki/rekor-ed25519.pem:
	openssl genpkey -algorithm ed25519 -out $@
	chmod 644 $@

pki/rekor-ed25519-pub.pem: pki/rekor-ed25519.pem
	openssl pkey -in $< -pubout -out $@

up: keys ## bring the stack up, export the caddy root, wait for readiness
	$(COMPOSE) up -d caddy
	@$(MAKE) caddy-root
	$(COMPOSE) up -d
	@echo "waiting for issuer discovery (TLS validated against caddy root)..."
	@for i in $$(seq 1 60); do \
	  curl --cacert $(CADDY_ROOT) -sf $(DISCOVERY) >/dev/null 2>&1 && { echo "issuer ready"; exit 0; }; \
	  sleep 2; \
	done; echo "issuer not ready in time" >&2; exit 1
	@echo "waiting for rekor /healthz (TLS validated against caddy root)..."
	@for i in $$(seq 1 30); do \
	  curl --cacert $(CADDY_ROOT) -sf https://rekor.127.0.0.1.sslip.io:3003/healthz 2>/dev/null | grep -q SERVING && { echo "rekor ready"; exit 0; }; \
	  sleep 2; \
	done; echo "rekor not ready in time" >&2; exit 1
	@echo "waiting for tesseract /healthz (TLS validated against caddy root)..."
	@for i in $$(seq 1 30); do \
	  curl --cacert $(CADDY_ROOT) -sf https://ct.127.0.0.1.sslip.io:6962/healthz >/dev/null 2>&1 && { echo "tesseract ready"; exit 0; }; \
	  sleep 2; \
	done; echo "tesseract not ready in time" >&2; exit 1
	@echo "stack ready"

preflight: keys ## bring up each service alone (no deps) and report init hangs
	@for svc in caddy keycloak fulcio rekor; do \
	  echo "== preflight: $$svc =="; \
	  $(COMPOSE) up --no-deps -d $$svc >/dev/null 2>&1 || echo "FAILED to start $$svc"; \
	  sleep 8; \
	  $(COMPOSE) ps $$svc; \
	  $(COMPOSE) logs --tail 20 $$svc; \
	  $(COMPOSE) down >/dev/null 2>&1; \
	  echo; \
	done

caddy-root: $(CADDY_ROOT) ## copy Caddy's internal CA root out of the container

$(CADDY_ROOT):
	@echo "waiting for caddy internal CA root..."
	@for i in $$(seq 1 30); do \
	  ( $(COMPOSE) cp caddy:/data/caddy/pki/authorities/local/root.crt $@ 2>/dev/null \
	    || podman cp strike-sigstore-local_caddy_1:/data/caddy/pki/authorities/local/root.crt $@ 2>/dev/null ) \
	    && { chmod 644 $@; echo "exported $@"; exit 0; }; \
	  sleep 2; \
	done; echo "caddy root not available (see first-run risk R-5)" >&2; exit 1

down: ## stop the stack, keep volumes
	$(COMPOSE) down

clean: ## stop the stack and delete volumes, keys and exported anchors
	$(COMPOSE) down --volumes
	rm -f pki/*.pem pki/*.crt pki/*.key

check-issuer: ## verify the issuer resolves identically from host and in-network
	@echo "== host (validated against caddy root) =="
	curl --cacert $(CADDY_ROOT) -sf $(DISCOVERY) | grep -o '"issuer":"[^"]*"'
	@echo "== in-network (same vantage as Fulcio) =="
	$(COMPOSE) --profile tools run --rm probe -sk $(DISCOVERY) | grep -o '"issuer":"[^"]*"'

token: $(CADDY_ROOT) ## print an OIDC id_token for tester@strike.localhost (aud sigstore)
	@curl --cacert $(CADDY_ROOT) -sf \
	  -d grant_type=password -d client_id=sigstore \
	  -d username=tester -d password=tester -d scope=openid \
	  $(ISSUER)/protocol/openid-connect/token \
	  | grep -o '"id_token":"[^"]*"' | sed 's/.*:"//;s/"$$//'

tsa-certchain: $(CADDY_ROOT) ## fetch the TSA certificate chain (PEM); always re-fetched -- the TSA mints a fresh signing cert per startup
	@echo "waiting for TSA certchain (TLS validated against caddy root)..."
	@for i in $$(seq 1 30); do \
	  curl --cacert $(CADDY_ROOT) -sf https://tsa.127.0.0.1.sslip.io:3004/api/v1/timestamp/certchain -o pki/tsa-certchain.pem \
	    && { echo "exported pki/tsa-certchain.pem"; exit 0; }; \
	  sleep 2; \
	done; echo "TSA certchain not available" >&2; exit 1

rekor-pubkey: pki/rekor-ed25519-pub.pem ## export the rekor log public key (for trust-root assembly)

# Persistent Fulcio fileca root (replaces ephemeralca so the CT log can pin a
# stable accepted root). Grouped target: one recipe produces both files.
pki/fulcio-root.crt pki/fulcio-root.key &:
	openssl ecparam -genkey -name prime256v1 -noout -out pki/fulcio-root.unenc.key
	openssl pkcs8 -topk8 -in pki/fulcio-root.unenc.key -out pki/fulcio-root.key -passout pass:fulcio
	openssl req -x509 -new -key pki/fulcio-root.unenc.key -out pki/fulcio-root.crt -days 365 \
	  -subj "/CN=strike-local-fulcio-ca" \
	  -addext "basicConstraints=critical,CA:TRUE" \
	  -addext "keyUsage=critical,keyCertSign,cRLSign"
	rm -f pki/fulcio-root.unenc.key
	chmod 644 pki/fulcio-root.crt pki/fulcio-root.key

# CT log (ctfe) signer key, ECDSA P256 SEC1. chmod 644: the nonroot TesseraCT
# container cannot read a 0600 key under rootless userns (same as the rekor key).
pki/ctfe.key:
	openssl ecparam -genkey -name prime256v1 -noout -out $@
	chmod 644 $@

pki/ctfe-pub.pem: pki/ctfe.key
	openssl ec -in $< -pubout -out $@

ctlog-pubkey: pki/ctfe-pub.pem ## export the CT log (ctfe) public key (for trust-root assembly)

conformance: ## cosign independent-verify of the golden bundles, offline (V gates exit; E/informational reported)
	@echo "== conformance: cosign independent verification of golden bundles (no insecure flags) =="
	@if cosign verify-blob-attestation \
	  --bundle ../../internal/verify/testdata/golden/sealed.sigstore.json \
	  --trusted-root ../../internal/verify/testdata/golden/trusted_root.json \
	  --certificate-identity tester@strike.localhost \
	  --certificate-oidc-issuer $(ISSUER) \
	  --type https://slsa.dev/provenance/v1 \
	  --check-claims=false >/dev/null 2>&1; then \
	    echo "  OK   sealed (V)"; \
          else \
	    { echo "  FAIL sealed (V) -- conformance gate failed" >&2; exit 1; }; \
          fi
	@for e in "engine-context https://istr.dev/strike/predicates/engine-context/v1" "informational https://istr.dev/strike/predicates/informational/v1"; do \
	  set -- $$e; \
	  if cosign verify-blob-attestation \
	      --bundle ../../internal/verify/testdata/golden/$$1.sigstore.json \
	      --trusted-root ../../internal/verify/testdata/golden/trusted_root.json \
	      --certificate-identity tester@strike.localhost \
	      --certificate-oidc-issuer $(ISSUER) \
	      --type $$2 --check-claims=false >/dev/null 2>&1; then \
	    echo "  OK   $$1 (reported, non-gating)"; \
	  else \
	    echo "  WARN $$1 verification failed (reported, non-gating)"; \
	  fi; \
	done
	@echo "conformance OK (V verified)"
