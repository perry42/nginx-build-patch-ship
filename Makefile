# Echo: Build It, Patch It, Ship It
# Prerequisites: Docker (with BuildKit), GNU make, Python 3.10+. Nothing else.
#
#   make all      build the .deb and the image, run the parity tests, scan, diff
#   make test     boot the original and our image and compare them (needs `make image`)
#   make verify   short proof of the fixes against the original (needs both images)
#   make help     list targets

ORIGINAL   ?= nginx:1.25-bookworm
PATCHED    ?= echo/nginx:1.25-patched
TRIVY_TAG  ?= 0.76.2
GRYPE_TAG  ?= v0.122.1
PY         ?= python
BUILD_FLAGS ?=
SCANDIR    ?= scans/rescan
# Grype keeps its database in $HOME/.cache, which is / in its container, not /root, so
# GRYPE_DB_CACHE_DIR points it at the grype-db volume. Without that every run downloaded its own copy.
# DB=frozen (default): update the scanner databases once at the start of `make scan`,
# then every later scan in the run uses that same copy, so the numbers cannot move
# in the middle of a run. DB=fresh: let every scan update the database itself.
DB         ?= frozen

# Docker Desktop on Windows (Git Bash) rewrites /paths in arguments; turn that off.
export MSYS_NO_PATHCONV = 1

ifeq ($(DB),fresh)
TRIVY_DB   :=
GRYPE_ENV  :=
else
TRIVY_DB   := --skip-db-update
GRYPE_ENV  := -e GRYPE_DB_AUTO_UPDATE=false
endif

TRIVY = docker run --rm -v $(CURDIR):/work -v trivy-cache:/root/.cache -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:$(TRIVY_TAG)
GRYPE = docker run --rm -v $(CURDIR):/work -v grype-db:/root/.cache/grype -e GRYPE_DB_CACHE_DIR=/root/.cache/grype -v //var/run/docker.sock:/var/run/docker.sock $(GRYPE_ENV) anchore/grype:$(GRYPE_TAG)

.PHONY: help all deb image deps test verify scan vex diff sizes clean

help:
	@echo "deb     build the nginx .deb from source into dist/ (build/Dockerfile)"
	@echo "image   build $(PATCHED) from the Containerfile (also builds the .deb)"
	@echo "deps    install the test requirements (pip)"
	@echo "test    parity tests: $(ORIGINAL) vs $(PATCHED)"
	@echo "verify  check the fixes: tests pass on ours, fail on the original (not alongside make test)"
	@echo "scan    Trivy and Grype on both images, same session, into $(SCANDIR)/ (DB=fresh to update per scan)"
	@echo "vex     rescan our image with vex.json applied (Trivy and Grype --vex)"
	@echo "diff    per-CVE diff of the scans into reports/cve-diff.generated.txt"
	@echo "sizes   image sizes, original vs ours"
	@echo "clean   remove dist/ and scan output"

all: image deps test scan vex diff sizes

# The .deb alone, exported to dist/ (the image build does this internally as well).
deb:
	docker build $(BUILD_FLAGS) -f build/Dockerfile --output type=local,dest=dist build
	@ls -l dist

image:
	docker build $(BUILD_FLAGS) -f Containerfile -t $(PATCHED) .

deps:
	$(PY) -m pip install -r test/requirements.txt

# Exits non-zero on any mismatch. Pass pytest options with ARGS="-k rewrite".
test:
	ORIGINAL_IMAGE=$(ORIGINAL) PATCHED_IMAGE=$(PATCHED) $(PY) -m pytest test -q $(ARGS)

# Quick proof of the fixes. Does not build or scan; needs both images. Never run it
# at the same time as `make test` (the fixtures remove each other's containers).
verify:
	$(PY) scripts/verify.py $(ORIGINAL) $(PATCHED)

# One database update per run, recorded next to the results. Skipped with DB=fresh.
dbupdate:
	mkdir -p $(SCANDIR)
ifeq ($(DB),fresh)
	@echo "DB=fresh: each scan updates its own database" > $(SCANDIR)/db-versions.txt
else
	$(TRIVY) image --download-db-only -q
	$(GRYPE) db update
	( $(TRIVY) --version; $(GRYPE) db status ) > $(SCANDIR)/db-versions.txt
endif
	@cat $(SCANDIR)/db-versions.txt

# Both images scanned back to back with the same pinned scanner versions, so a
# vulnerability database update cannot show up as a difference between them.
scan: dbupdate
	mkdir -p $(SCANDIR)
	$(TRIVY) image $(TRIVY_DB) --scanners vuln --format json --list-all-pkgs -q $(ORIGINAL) > $(SCANDIR)/base-trivy.json
	$(TRIVY) image $(TRIVY_DB) --scanners vuln -q $(ORIGINAL) > $(SCANDIR)/base-trivy.txt
	$(TRIVY) image $(TRIVY_DB) --scanners vuln --format json --list-all-pkgs -q $(PATCHED) > $(SCANDIR)/fixed-trivy.json
	$(TRIVY) image $(TRIVY_DB) --scanners vuln -q $(PATCHED) > $(SCANDIR)/fixed-trivy.txt
	$(GRYPE) $(ORIGINAL) -o json -q > $(SCANDIR)/base-grype.json
	$(GRYPE) $(ORIGINAL) -q > $(SCANDIR)/base-grype.txt
	$(GRYPE) $(PATCHED) -o json -q > $(SCANDIR)/fixed-grype.json
	$(GRYPE) $(PATCHED) -q > $(SCANDIR)/fixed-grype.txt

# Scan our image again with the OpenVEX document applied; the zlib row should vanish.
vex:
	mkdir -p $(SCANDIR)
	$(TRIVY) image $(TRIVY_DB) --scanners vuln --vex /work/vex.json --format json --list-all-pkgs -q $(PATCHED) > $(SCANDIR)/vex-trivy.json
	$(TRIVY) image $(TRIVY_DB) --scanners vuln --vex /work/vex.json -q $(PATCHED) > $(SCANDIR)/vex-trivy.txt
	$(GRYPE) $(PATCHED) --vex /work/vex.json -o json -q > $(SCANDIR)/vex-grype.json
	$(GRYPE) $(PATCHED) --vex /work/vex.json -q > $(SCANDIR)/vex-grype.txt
	cd $(SCANDIR) && $(PY) ../../scripts/vexdiff.py > ../../reports/vex-diff.generated.txt
	@cat reports/vex-diff.generated.txt

diff:
	cd $(SCANDIR) && ( $(PY) ../../scripts/cvediff.py; echo; $(PY) ../../scripts/cvecause.py ) > ../../reports/cve-diff.generated.txt
	@cat reports/cve-diff.generated.txt

sizes:
	@docker image ls --format '{{.Repository}}:{{.Tag}}  {{.Size}}' | grep -F -e '$(ORIGINAL)' -e '$(PATCHED)'

clean:
	rm -rf dist $(SCANDIR)
