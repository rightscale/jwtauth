SHELL=/bin/bash

# alias for 'vendor'
depend: vendor

# installs glide binary, if not present
$(GOPATH)/bin/dep:
	go get -v -u github.com/golang/dep/cmd/dep

# install vendored dependencies, as needed
vendor: $(GOPATH)/bin/dep Gopkg.lock
	@dep ensure --vendor-only

# installs goimports binary, if not present
$(GOPATH)/bin/goimports:
	@go get golang.org/x/tools/cmd/goimports

# Look for all Go files, skipping hidden dirs and vendor, and goa-generated dir names
fmt: $(GOPATH)/bin/goimports
	@files=$$(find . -type f -not -path '*/\.*' -not -path "./vendor/*" -name "*\.go" | grep -Ev '/(gen)/'); \
	$(GOPATH)/bin/goimports -w -l $$files

$(GOPATH)/bin/golint:
	@go get golang.org/x/lint/golint && golint

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
