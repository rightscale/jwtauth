SHELL=/bin/bash

# enable go-modules for go v1.11 and v1.12
export GO111MODULE=on

# alias for 'vendor'
depend: vendor

# install vendored dependencies for legacy support; not needed by go modules
vendor: go.mod go.sum
	@for sleeper in 0 1 2 4 8 16 32; do sleep $$sleeper; go mod vendor; if [ $$? = 0 ]; then break; else rm -rf vendor; fi; done
	@if [ -d vendor ]; then touch vendor; else exit 1; fi

# installs goimports binary, if not present
$(GOPATH)/bin/goimports:
	@go get golang.org/x/tools/cmd/goimports

# Look for all Go files, skipping hidden dirs and vendor, and goa-generated dir names
fmt: $(GOPATH)/bin/goimports
	@files=$$(find . -type f -not -path '*/\.*' -not -path "./vendor/*" -name "*\.go" | grep -Ev '/(gen)/'); \
	$(GOPATH)/bin/goimports -w -l $$files

$(GOPATH)/bin/golint:
	@go get golang.org/x/lint/golint

lint: $(GOPATH)/bin/golint
	@if gofmt -l . | egrep -v '^vendor/' | grep .go; then \
	  echo "^- Repo contains improperly formatted go files; run make fmt" && exit 1; \
	  else echo "All .go files formatted correctly"; fi
	@VET_OUTPUT=$$(go vet `go list ./... | grep -v /vendor/` 2>&1 | grep -v "exit status 1" | grep -v "unrecognized printf verb 'n'" || true) && if [[ -n $$VET_OUTPUT ]]; then echo "Your changes introduced new 'go vet ./...' warnings:" && echo $$VET_OUTPUT && exit 1; fi
	@for d in $$(find . -type f -not -path '*/\.*' -not -path "./vendor/*" -name "*\.go" | grep -Ev '/(design|gen)/'); do \
	  golint -set_exit_status $$d; \
	done

$(GOPATH)/bin/ginkgo:
	@go get github.com/onsi/ginkgo/ginkgo

test: lint $(GOPATH)/bin/ginkgo
	@ginkgo -r -cover

# installs goimports binary, if not present
$(GOPATH)/bin/goveralls:
	@go get github.com/mattn/goveralls

coverage: $(GOPATH)/bin/goveralls
	@goveralls -coverprofile=jwtauth.coverprofile -service=travis-ci -repotoken $COVERALLS_TOKEN
