# Echo: Build It, Patch It, Ship It
# Prerequisites: Docker (with BuildKit), GNU make, Python 3.10+. Nothing else.
#
#   make all      build the .deb and the image, run the parity tests, scan, diff
#   make test     boot the original and our image and compare them (needs `make image`)
#   make help     list targets

ORIGINAL   ?= nginx:1.25-bookworm
PATCHED    ?= echo/nginx:1.25-patched
TRIVY_TAG  ?= 0.76.2
GRYPE_TAG  ?= v0.122.1
PY         ?= python
BUILD_FLAGS ?=
SCANDIR    ?= scans/rescan

# Docker Desktop on Windows (Git Bash) rewrites /paths in arguments; turn that off.
export MSYS_NO_PATHCONV = 1

TRIVY = docker run --rm -v trivy-cache:/root/.cache -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:$(TRIVY_TAG)
GRYPE = docker run --rm -v grype-db:/root/.cache/grype -v //var/run/docker.sock:/var/run/docker.sock anchore/grype:$(GRYPE_TAG)

.PHONY: help all deb image deps test scan diff sizes clean

help:
	@echo "deb     build the nginx .deb from source into dist/ (build/Dockerfile)"
	@echo "image   build $(PATCHED) from the Containerfile (also builds the .deb)"
	@echo "deps    install the test requirements (pip)"
	@echo "test    parity tests: $(ORIGINAL) vs $(PATCHED)"
	@echo "scan    Trivy and Grype on both images, same session, into $(SCANDIR)/"
	@echo "diff    per-CVE diff of the scans into reports/cve-diff.generated.txt"
	@echo "sizes   image sizes, original vs ours"
	@echo "clean   remove dist/ and scan output"

all: image deps test scan diff sizes

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

# Both images scanned back to back with the same pinned scanner versions, so a
# vulnerability database update cannot show up as a difference between them.
scan:
	mkdir -p $(SCANDIR)
	$(TRIVY) image --scanners vuln --format json --list-all-pkgs -q $(ORIGINAL) > $(SCANDIR)/base-trivy.json
	$(TRIVY) image --scanners vuln -q $(ORIGINAL) > $(SCANDIR)/base-trivy.txt
	$(TRIVY) image --scanners vuln --format json --list-all-pkgs -q $(PATCHED) > $(SCANDIR)/fixed-trivy.json
	$(TRIVY) image --scanners vuln -q $(PATCHED) > $(SCANDIR)/fixed-trivy.txt
	$(GRYPE) $(ORIGINAL) -o json -q > $(SCANDIR)/base-grype.json
	$(GRYPE) $(ORIGINAL) -q > $(SCANDIR)/base-grype.txt
	$(GRYPE) $(PATCHED) -o json -q > $(SCANDIR)/fixed-grype.json
	$(GRYPE) $(PATCHED) -q > $(SCANDIR)/fixed-grype.txt

diff:
	cd $(SCANDIR) && ( $(PY) ../../scripts/cvediff.py; echo; $(PY) ../../scripts/cvecause.py ) > ../../reports/cve-diff.generated.txt
	@cat reports/cve-diff.generated.txt

sizes:
	@docker image ls --format '{{.Repository}}:{{.Tag}}  {{.Size}}' | grep -F -e '$(ORIGINAL)' -e '$(PATCHED)'

clean:
	rm -rf dist $(SCANDIR)
