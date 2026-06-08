# Local sigstore harness. Rootless Podman by default; override COMPOSE to use
# docker compose. Not part of the strike trusted binary.
COMPOSE   ?= podman compose
ISSUER    := https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore
DISCOVERY := $(ISSUER)/.well-known/openid-configuration
CADDY_ROOT := pki/caddy-root.crt

.PHONY: keys up down clean caddy-root check-issuer preflight token tsa-certchain

keys: pki/rekor-ed25519.pem ## generate the rekor log signer key (ed25519)

pki/rekor-ed25519.pem:
	openssl genpkey -algorithm ed25519 -out $@
	chmod 644 $@

up: keys ## bring the stack up, export the caddy root, wait for readiness
	$(COMPOSE) up -d caddy
	@$(MAKE) caddy-root
	$(COMPOSE) up -d
	@echo "waiting for issuer discovery (TLS validated against caddy root)..."
	@for i in $$(seq 1 60); do \
	  curl --cacert $(CADDY_ROOT) -sf $(DISCOVERY) >/dev/null 2>&1 && { echo "issuer ready"; exit 0; }; \
	  sleep 2; \
	done; echo "issuer not ready in time" >&2; exit 1
	@echo "waiting for rekor /healthz..."
	@for i in $$(seq 1 30); do \
	  curl -sf http://localhost:3003/healthz 2>/dev/null | grep -q SERVING && { echo "rekor ready"; exit 0; }; \
	  sleep 2; \
	done; echo "rekor not ready in time" >&2; exit 1
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
	    && { echo "exported $@"; exit 0; }; \
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

tsa-certchain: pki/tsa-certchain.pem ## fetch the TSA certificate chain (PEM)

pki/tsa-certchain.pem:
	@echo "waiting for TSA certchain..."
	@for i in $$(seq 1 30); do \
	  curl -sf http://localhost:3004/api/v1/timestamp/certchain -o $@ \
	    && { echo "exported $@"; exit 0; }; \
	  sleep 2; \
	done; echo "TSA certchain not available" >&2; exit 1
